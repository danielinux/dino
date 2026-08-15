project('Dino', 'c', 'cpp', 'vala', license: 'GPL-3.0', meson_version: '>=1.3.0')

# Almost every C warning in this build comes out of valac-generated C, not out of
# anything anyone wrote: unused `_tmpN_`/`_inner_errorN_` temporaries, `__catch0_*`
# labels, unused `*_ref`/`*_finish` boilerplate, and — the single largest group —
# `-Wdiscarded-qualifiers` raised inside glib's own gatomic.h, once per generated
# get_type() via g_once_init_enter(). None of it is actionable here, and 5k lines of
# it buries the handful of warnings that ARE real (e.g. the %llu/uint64 format bugs).
# Silencing these takes the plugin build from ~213 warnings to ~5, all genuine.
#
# Deliberately NOT suppressed: -Wincompatible-pointer-types (GCC 14+ makes these
# errors by default and they catch real VAPI drift) and -Wformat (real bugs).
# Hand-written C keeps full warnings by opting back in per target — see
# plugins/x3dhpq/meson.build, which builds wolfssl_helper.c separately for exactly
# this reason.
cc = meson.get_compiler('c')
add_project_arguments(cc.get_supported_arguments([
    '-Wno-unused-but-set-variable',
    '-Wno-unused-variable',
    '-Wno-unused-function',
    '-Wno-unused-label',
    '-Wno-discarded-qualifiers',
    '-Wno-duplicate-decl-specifier',
]), language: 'c')

fs = import('fs')
gnome = import('gnome')
i18n = import('i18n')
python = import('python')

# plugin_crypto is enabled if any of the crypto plugins is enabled, auto if
# none of them are explicitly enabled but at least one is set to auto, or
# disabled if all of them are disabled.
plugin_crypto = get_option('plugin-ice')
foreach plugin : ['plugin-ice', 'plugin-omemo', 'plugin-rtp']
    if get_option(plugin).enabled() and not plugin_crypto.enabled()
        plugin_crypto = get_option(plugin)
    elif get_option(plugin).allowed() and not plugin_crypto.allowed()
        plugin_crypto = get_option(plugin)
    endif
endforeach

dep_gdk_pixbuf = dependency('gdk-pixbuf-2.0')
dep_gee = dependency('gee-0.8')
dep_gio = dependency('gio-2.0')
dep_glib = dependency('glib-2.0')
dep_gnutls = dependency('gnutls', disabler: true, required: get_option('plugin-ice'))
dep_gmodule = dependency('gmodule-2.0')
dep_gpgme = dependency('gpgme', disabler: true, required: get_option('plugin-openpgp'))
dep_gstreamer = dependency('gstreamer-1.0', disabler: true, required: get_option('plugin-rtp'))
dep_gstreamer_app = dependency('gstreamer-app-1.0', disabler: true, required: get_option('plugin-rtp'))
dep_gstreamer_audio = dependency('gstreamer-audio-1.0', disabler: true, required: get_option('plugin-rtp'))
dep_gstreamer_rtp = dependency('gstreamer-rtp-1.0', disabler: true, required: get_option('plugin-rtp'))
dep_gstreamer_video = dependency('gstreamer-video-1.0', disabler: true, required: get_option('plugin-rtp'))
dep_gtk4 = dependency('gtk4')
dep_icu_uc = dependency('icu-uc')
dep_libadwaita = dependency('libadwaita-1', version: '>=1.5')
dep_libcanberra = dependency('libcanberra', disabler: true, required: get_option('plugin-notification-sound'))
dep_libgcrypt = dependency('libgcrypt', disabler: true, required: plugin_crypto)
dep_libqrencode = dependency('libqrencode', disabler: true, required: get_option('plugin-omemo'))
dep_libsrtp2 = dependency('libsrtp2', disabler: true, required: plugin_crypto)
dep_libomemo_c = dependency('libomemo-c', disabler: true, required: get_option('plugin-omemo'))
dep_libsoup = dependency('libsoup-3.0', disabler: true, required: get_option('plugin-http-files'))
dep_wolfssl = dependency('wolfssl', disabler: true, required: get_option('plugin-x3dhpq'))
dep_nice = dependency('nice', version: '>=0.1.15', disabler: true, required: get_option('plugin-ice'))
dep_m = meson.get_compiler('c').find_library('m', required: false)
dep_sqlite3 = dependency('sqlite3', version: '>=3.24')

dep_webrtc_audio_processing = dependency('webrtc-audio-processing-1', required: false)
if not dep_webrtc_audio_processing.found()
    dep_webrtc_audio_processing = dependency('webrtc-audio-processing', version: ['>=0.2'], required: false)
endif
if not dep_webrtc_audio_processing.found()
    dep_webrtc_audio_processing = dependency('webrtc-audio-processing-2', required: false)
endif
if not dep_webrtc_audio_processing.found()
    dep_webrtc_audio_processing = disabler()
endif

prog_git = find_program('git', required: false)
prog_python = python.find_installation()

if import('fs').is_file('VERSION') and meson.version().version_compare('>=1.4.0')
    version_file = files('VERSION')[0]
    version_file_path = version_file.full_path()
else
    version_file = 'invalid'
    version_file_path = meson.current_source_dir() / 'VERSION'
endif

default_install_rpath = ''
if get_option('set-install-rpath')
    default_install_rpath = get_option('prefix') / get_option('libdir')
endif

subdir('qlite')
subdir('xmpp-vala')
subdir('libdino')
subdir('main')
subdir('crypto-vala')
subdir('plugins')
