dependencies = [
    dep_dino,
    dep_gee,
    dep_glib,
    dep_gio,
    dep_gmodule,
    dep_gtk4,
    dep_libadwaita,
    dep_qlite,
    dep_wolfssl,
    dep_xmpp_vala,
]

if not dep_wolfssl.found()
    summary('End-to-end encryption using x3dhpq (x3dhpq)', false, bool_yn: true, section: 'Plugins')
    subdir_done()
endif

sources = files(
    'src/contact_details_provider.vala',
    'src/database.vala',
    'src/encryption_list_entry.vala',
    'src/encryption_preferences_entry.vala',
    'src/manager.vala',
    'src/plugin.vala',
    'src/protocol/groupmsg.vala',
    'src/protocol/groupsession.vala',
    'src/protocol/groupshare.vala',
    'src/protocol/membership_journal.vala',
    'src/protocol/pairwise.vala',
    'src/protocol/namespaces.vala',
    'src/protocol/senderchain.vala',
    'src/register_plugin.vala',
    'src/stream_module.vala',
    'src/util.vala',
    'src/native/wolfssl.vala',
    'src/native/wolfssl_helper.c',
)

c_args = [
    '-DG_LOG_DOMAIN="x3dhpq"',
]

vala_args = [
    '--vapidir', meson.current_source_dir() / 'vapi',
]

lib_x3dhpq = shared_library(
    'x3dhpq',
    sources,
    name_prefix: '',
    c_args: c_args,
    vala_args: vala_args,
    include_directories: include_directories('src'),
    dependencies: dependencies,
    install: true,
    install_dir: get_option('libdir') / get_option('plugindir'),
    install_rpath: default_install_rpath,
)

dep_x3dhpq = declare_dependency(link_with: lib_x3dhpq, include_directories: include_directories('.'))
summary('End-to-end encryption using x3dhpq (x3dhpq)', dep_x3dhpq.found(), bool_yn: true, section: 'Plugins')

test_sources = [
    'tests/common.vala',
    'tests/testcase.vala',
    'tests/pairwise.vala',
    'tests/groupsession.vala',
    'tests/membership_journal.vala',
]

exe_x3dhpq_test = executable(
    'x3dhpq-test',
    test_sources,
    c_args: c_args,
    vala_args: vala_args,
    include_directories: include_directories('src'),
    dependencies: dependencies + dep_x3dhpq,
    build_rpath: '$ORIGIN',
    install: false,
)
test('Tests for x3dhpq', exe_x3dhpq_test)
