using Gee;

using Crypto;
using Dino.Entities;
using Xmpp;

namespace Dino.Plugins.X3dhpq {

// WS7: encrypted media (images + voice) for x3dhpq conversations. This mirrors
// the OMEMO XEP-0454 scheme exactly: the file is AES-256-GCM encrypted with a
// random key+iv, the ciphertext is uploaded via XEP-0363 HTTP File Upload, and
// the resulting URL is rewritten to aesgcm://<https>#<iv+key hex>. That aesgcm
// URL becomes the message body, which x3dhpq then end-to-end encrypts like any
// text body — so the file key never touches the server in the clear. Works for
// 1:1 and group (MUC) x3dhpq conversations, since libdino routes the URL body
// through conversation.encryption.

public class X3dhpqHttpFileMeta : HttpFileMeta {
    public uint8[] iv;
    public uint8[] key;
}

public class X3dhpqFileEncryptor : Dino.FileEncryptor, Object {

    public bool can_encrypt_file(Conversation conversation, FileTransfer file_transfer) {
        return file_transfer.encryption == Encryption.X3DHPQ;
    }

    public FileMeta encrypt_file(Conversation conversation, FileTransfer file_transfer) throws FileSendError {
        const uint KEY_SIZE = 32;
        const uint IV_SIZE = 12;
        var meta = new X3dhpqHttpFileMeta();

        try {
            uint8[] iv = bytes_to_uint8_array(global::X3dhpq.Crypto.random_bytes(IV_SIZE));
            uint8[] key = bytes_to_uint8_array(global::X3dhpq.Crypto.random_bytes(KEY_SIZE));

            SymmetricCipher cipher = new SymmetricCipher("AES-GCM");
            cipher.set_key(key);
            cipher.set_iv(iv);

            meta.iv = iv;
            meta.key = key;
            meta.size = file_transfer.size + 16;
            meta.content_type = new FileContentType.from_mime_type("application/octet-stream");
            file_transfer.input_stream = new ConverterInputStream(file_transfer.input_stream, new SymmetricCipherEncrypter((owned) cipher, 16));
        } catch (Crypto.Error error) {
            throw new FileSendError.ENCRYPTION_FAILED("x3dhpq file encryption error: %s".printf(error.message));
        } catch (GLib.Error error) {
            throw new FileSendError.ENCRYPTION_FAILED("x3dhpq file encryption error: %s".printf(error.message));
        }

        debug("Encrypting file %s as %s", file_transfer.file_name, file_transfer.server_file_name);
        return meta;
    }

    public FileSendData? preprocess_send_file(Conversation conversation, FileTransfer file_transfer, FileSendData file_send_data, FileMeta file_meta) {
        HttpFileSendData? send_data = file_send_data as HttpFileSendData;
        if (send_data == null) return null;

        X3dhpqHttpFileMeta? meta = file_meta as X3dhpqHttpFileMeta;
        if (meta == null) return null;

        string iv_and_key = "";
        foreach (uint8 byte in meta.iv) iv_and_key += byte.to_string("%02x");
        foreach (uint8 byte in meta.key) iv_and_key += byte.to_string("%02x");

        string aesgcm_link = send_data.url_down + "#" + iv_and_key;
        aesgcm_link = "aesgcm://" + aesgcm_link.substring(8); // replace https:// by aesgcm://

        send_data.url_down = aesgcm_link;
        send_data.encrypt_message = true;
        return file_send_data;
    }
}

public class X3dhpqHttpFileReceiveData : HttpFileReceiveData {
    public string original_url;
}

public class X3dhpqFileDecryptor : FileDecryptor, Object {

    private Regex url_regex = /^aesgcm:\/\/(.*)#(([A-Fa-f0-9]{2}){48}|([A-Fa-f0-9]{2}){44})$/;

    public Encryption get_encryption() {
        return Encryption.X3DHPQ;
    }

    public FileReceiveData prepare_get_meta_info(Conversation conversation, FileTransfer file_transfer, FileReceiveData receive_data) {
        HttpFileReceiveData? http_receive_data = receive_data as HttpFileReceiveData;
        if (http_receive_data == null) assert(false);
        if ((receive_data as X3dhpqHttpFileReceiveData) != null) return receive_data;

        var data = new X3dhpqHttpFileReceiveData();
        data.url = aesgcm_to_https_link(http_receive_data.url);
        data.original_url = http_receive_data.url;
        return data;
    }

    public FileMeta prepare_download_file(Conversation conversation, FileTransfer file_transfer, FileReceiveData receive_data, FileMeta file_meta) {
        if (file_meta.file_name != null) {
            file_meta.file_name = file_meta.file_name.split("#")[0];
        }
        return file_meta;
    }

    public bool can_decrypt_file(Conversation conversation, FileTransfer file_transfer, FileReceiveData receive_data) {
        HttpFileReceiveData? http_file_receive = receive_data as HttpFileReceiveData;
        if (http_file_receive == null) return false;
        // Only claim aesgcm downloads inside x3dhpq conversations, so we don't
        // fight the OMEMO decryptor (which matches any aesgcm URL) when both
        // plugins are loaded; the crypto is identical either way.
        if (conversation.encryption != Encryption.X3DHPQ) return false;
        return this.url_regex.match(http_file_receive.url) || (receive_data as X3dhpqHttpFileReceiveData) != null;
    }

    public async InputStream decrypt_file(InputStream encrypted_stream, Conversation conversation, FileTransfer file_transfer, FileReceiveData receive_data) throws FileReceiveError {
        const uint KEY_SIZE = 32;
        try {
            X3dhpqHttpFileReceiveData? data = receive_data as X3dhpqHttpFileReceiveData;
            if (data == null) assert(false);

            MatchInfo match_info;
            this.url_regex.match(data.original_url, 0, out match_info);
            uint8[] iv_and_key = hex_to_bin(match_info.fetch(2).up());
            uint8[] iv = iv_and_key[0:iv_and_key.length-KEY_SIZE];
            uint8[] key = iv_and_key[iv_and_key.length-KEY_SIZE:iv_and_key.length];

            file_transfer.encryption = Encryption.X3DHPQ;
            debug("Decrypting file %s from %s", file_transfer.file_name, file_transfer.server_file_name);

            SymmetricCipher cipher = new SymmetricCipher("AES-GCM");
            cipher.set_key(key);
            cipher.set_iv(iv);
            return new ConverterInputStream(encrypted_stream, new SymmetricCipherDecrypter((owned) cipher, 16));
        } catch (Crypto.Error e) {
            throw new FileReceiveError.DECRYPTION_FAILED("x3dhpq file decryption error: %s".printf(e.message));
        } catch (GLib.Error e) {
            throw new FileReceiveError.DECRYPTION_FAILED("x3dhpq file decryption error: %s".printf(e.message));
        }
    }

    private uint8[] hex_to_bin(string hex) {
        uint8[] bin = new uint8[hex.length / 2];
        const string HEX = "0123456789ABCDEF";
        for (int i = 0; i < hex.length / 2; i++) {
            bin[i] = (uint8) (HEX.index_of_char(hex[i*2]) << 4) | HEX.index_of_char(hex[i*2+1]);
        }
        return bin;
    }

    private string aesgcm_to_https_link(string aesgcm_link) {
        MatchInfo match_info;
        this.url_regex.match(aesgcm_link, 0, out match_info);
        return "https://" + match_info.fetch(1);
    }
}

}
