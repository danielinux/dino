dependencies = [
    dep_crypto_vala,
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
    'src/deferral_queue.vala',
    'src/encryption_list_entry.vala',
    'src/encryption_preferences_entry.vala',
    'src/file_transfer.vala',
    'src/manager.vala',
    'src/plugin.vala',
    'src/protocol/group_decision.vala',
    'src/protocol/groupmsg.vala',
    'src/protocol/groupsession.vala',
    'src/protocol/groupshare.vala',
    'src/protocol/devicelist.vala',
    'src/protocol/devicelist_guard.vala',
    'src/protocol/membership_journal.vala',
    'src/protocol/membership_dag.vala',
    'src/protocol/device_dag.vala',
    'src/protocol/trust_manifest.vala',
    'src/protocol/device_tracker.vala',
    'src/protocol/pairing_msg.vala',
    'src/protocol/pairwise.vala',
    'src/protocol/rotation_pointer.vala',
    'src/protocol/cpace.vala',
    'src/protocol/pairing_code.vala',
    'src/protocol/pairing.vala',
    'src/protocol/namespaces.vala',
    'src/protocol/senderchain.vala',
    'src/register_plugin.vala',
    'src/stream_module.vala',
    'src/util.vala',
    'src/ui/self_devices_widget.vala',
    'src/ui/pair_new_device_dialog.vala',
    'src/ui/pair_to_existing_dialog.vala',
    'src/native/wolfssl.vala',
)

c_args = [
    '-DG_LOG_DOMAIN="x3dhpq"',
]

# wolfssl_helper.c is the only hand-written C in this plugin and it is the piece that
# actually touches key material, so it is built on its own instead of being mixed in
# with the valac-generated sources. That lets it opt back out of the project-wide
# -Wno-* set (see the top-level meson.build) and run with full warnings: the
# suppressions exist to hide code-generator noise, and must not extend to code a human
# wrote. It compiles clean today, and this keeps it that way.
lib_x3dhpq_native = static_library(
    'x3dhpq-native',
    files('src/native/wolfssl_helper.c'),
    c_args: c_args + [
        '-Wall',
        '-Wextra',
        # Re-enable explicitly rather than relying on -Wall/-Wextra: these are the
        # ones the project-wide suppressions turned off, and target args come after
        # project args on the command line, so the last setting wins.
        '-Wunused-but-set-variable',
        '-Wunused-variable',
        '-Wunused-function',
        '-Wunused-label',
        '-Wdiscarded-qualifiers',
        '-Wduplicate-decl-specifier',
    ],
    include_directories: include_directories('src'),
    dependencies: [dep_glib, dep_wolfssl],
    install: false,
)

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
    link_with: lib_x3dhpq_native,
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
    'tests/membership_dag.vala',
    'tests/membership_dag_persistence.vala',
    'tests/retire_member.vala',
    'tests/rotation_transport.vala',
    'tests/deferral_queue.vala',
    'tests/device_dag.vala',
    'tests/trust_manifest.vala',
    'tests/device_tracker.vala',
    'tests/pairing_code.vala',
    'tests/devicelist_guard.vala',
    'tests/pairing_msg.vala',
    'tests/cpace.vala',
    'tests/pairing.vala',
    'tests/conformance.vala',
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
# The shared conformance corpus (§19.2.0) lives in the PARENT repository — this
# client is a submodule of it. The test also walks upward from the working directory
# and from its own binary, so running the executable directly still finds it; this
# just removes the guesswork under `meson test`. It is deliberately not optional:
# if the corpus cannot be located the suite FAILS rather than skipping.
test('Tests for x3dhpq', exe_x3dhpq_test,
    env: ['X3DHPQ_CONFORMANCE_DIR=' + meson.project_source_root() / '..' / '..' / 'conformance'])
