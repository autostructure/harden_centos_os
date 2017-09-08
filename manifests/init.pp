# Class: harden_centos_os
# ===========================
#
# Full description of class harden_centos_os here.
#
# Parameters
# ----------
#
# Document parameters here.
#
# * `sample parameter`
# Explanation of what this parameter affects and what it defaults to.
# e.g. "Specify one or more upstream ntp servers as an array."
#
# Variables
# ----------
#
# Here you should define a list of variables that this module would require.
#
# * `sample variable`
#  Explanation of how this variable affects the function of this class and if
#  it has a default. e.g. "The parameter enc_ntp_servers must be set by the
#  External Node Classifier as a comma separated list of hostnames." (Note,
#  global variables should be avoided in favor of class parameters as
#  of Puppet 2.6.)
#
# Examples
# --------
#
# @example
#    class { 'harden_centos_os':
#      servers => [ 'pool.ntp.org', 'ntp.local.company.com' ],
#    }
#
# Authors
# -------
#
# Author Name <jeff@autostructure.com>
#
# Copyright
# ---------
#
# Copyright 2017 Autostructure.
#
class harden_centos_os(
  String $motd,
  String $issue,
  Array $ntp_servers,
  Boolean $ensure_mounting_of_cramfs_filesystems_is_disabled,
  Boolean $ensure_mounting_of_freevxfs_filesystems_is_disabled,
  Boolean $ensure_mounting_of_jffs2_filesystems_is_disabled,
  Boolean $ensure_mounting_of_hfs_filesystems_is_disabled,
  Boolean $ensure_mounting_of_hfsplus_filesystems_is_disabled,
  Boolean $ensure_mounting_of_squashfs_filesystems_is_disabled,
  Boolean $ensure_mounting_of_udf_filesystems_is_disabled,
  Boolean $ensure_mounting_of_fat_filesystems_is_disabled,
  Boolean $ensure_separate_partition_exists_for__tmp,
  Boolean $ensure_nodev_option_set_on__tmp_partition,
  Boolean $ensure_nosuid_option_set_on__tmp_partition,
  Boolean $ensure_noexec_option_set_on__tmp_partition,
  Boolean $ensure_separate_partition_exists_for__var,
  Boolean $ensure_separate_partition_exists_for__var_tmp,
  Boolean $ensure_nodev_option_set_on__var_tmp_partition,
  Boolean $ensure_nosuid_option_set_on__var_tmp_partition,
  Boolean $ensure_noexec_option_set_on__var_tmp_partition,
  Boolean $ensure_separate_partition_exists_for__var_log,
  Boolean $ensure_separate_partition_exists_for__var_log_audit,
  Boolean $ensure_separate_partition_exists_for__home,
  Boolean $ensure_nodev_option_set_on__home_partition,
  Boolean $ensure_nodev_option_set_on__dev_shm_partition,
  Boolean $ensure_nosuid_option_set_on__dev_shm_partition,
  Boolean $ensure_noexec_option_set_on__dev_shm_partition,
  Boolean $ensure_nodev_option_set_on_removable_media_partitions,
  Boolean $ensure_nosuid_option_set_on_removable_media_partitions,
  Boolean $ensure_noexec_option_set_on_removable_media_partitions,
  Boolean $ensure_sticky_bit_is_set_on_all_world_writable_directories,
  Boolean $ensure_package_manager_repositories_are_configured,
  Boolean $ensure_gpg_keys_are_configured,
  Boolean $ensure_gpgcheck_is_globally_activated,
  Boolean $ensure_aide_is_installed,
  Boolean $ensure_filesystem_integrity_is_regularly_checked,
  Boolean $ensure_permissions_on_bootloader_config_are_configured,
  Boolean $ensure_bootloader_password_is_set,
  Boolean $ensure_authentication_required_for_single_user_mode,
  Boolean $ensure_core_dumps_are_restricted,
  Boolean $ensure_xd_nx_support_is_enabled,
  Boolean $ensure_address_space_layout_randomization_aslr_is_enabled,
  Boolean $ensure_prelink_is_disabled,
  Boolean $ensure_selinux_is_not_disabled_in_bootloader_configuration,
  Boolean $ensure_the_selinux_state_is_enforcing,
  Boolean $ensure_selinux_policy_is_configured,
  Boolean $ensure_setroubleshoot_is_not_installed,
  Boolean $ensure_the_mcs_translation_service_is_not_installed,
  Boolean $ensure_no_unconfined_daemons_exist,
  Boolean $ensure_selinux_is_installed,
  Boolean $ensure_message_of_the_day_is_configured_properly,
  Boolean $ensure_local_login_warning_banner_is_configured_properly,
  Boolean $ensure_remote_login_warning_banner_is_configured_properly,
  Boolean $ensure_permissions_on__etc_motd_are_configured,
  Boolean $ensure_permissions_on__etc_issue_are_configured,
  Boolean $ensure_permissions_on__etc_issue_net_are_configured,
  Boolean $ensure_gdm_login_banner_is_configured,
  Boolean $ensure_updates_patches_and_additional_security_software_are_installed,
  Boolean $ensure_chargen_services_are_not_enabled,
  Boolean $ensure_daytime_services_are_not_enabled,
  Boolean $ensure_discard_services_are_not_enabled,
  Boolean $ensure_echo_services_are_not_enabled,
  Boolean $ensure_time_services_are_not_enabled,
  Boolean $ensure_tftp_server_is_not_enabled,
  Boolean $ensure_xinetd_is_not_enabled,
  Boolean $ensure_time_synchronization_is_in_use,
  Boolean $ensure_ntp_is_configured,
  Boolean $ensure_chrony_is_configured,
  Boolean $ensure_x_window_system_is_not_installed,
  Boolean $ensure_avahi_server_is_not_enabled,
  Boolean $ensure_cups_is_not_enabled,
  Boolean $ensure_dhcp_server_is_not_enabled,
  Boolean $ensure_ldap_server_is_not_enabled,
  Boolean $ensure_nfs_and_rpc_are_not_enabled,
  Boolean $ensure_dns_server_is_not_enabled,
  Boolean $ensure_ftp_server_is_not_enabled,
  Boolean $ensure_http_server_is_not_enabled,
  Boolean $ensure_imap_and_pop3_server_is_not_enabled,
  Boolean $ensure_samba_is_not_enabled,
  Boolean $ensure_http_proxy_server_is_not_enabled,
  Boolean $ensure_snmp_server_is_not_enabled,
  Boolean $ensure_mail_transfer_agent_is_configured_for_local_only_mode,
  Boolean $ensure_nis_server_is_not_enabled,
  Boolean $ensure_rsh_server_is_not_enabled,
  Boolean $ensure_telnet_server_is_not_enabled,
  Boolean $ensure_tftp__socket_server_is_not_enabled,
  Boolean $ensure_rsync_service_is_not_enabled,
  Boolean $ensure_talk_server_is_not_enabled,
  Boolean $ensure_nis_client_is_not_installed,
  Boolean $ensure_rsh_client_is_not_installed,
  Boolean $ensure_talk_client_is_not_installed,
  Boolean $ensure_telnet_client_is_not_installed,
  Boolean $ensure_ldap_client_is_not_installed,
  Boolean $ensure_ip_forwarding_is_disabled,
  Boolean $ensure_packet_redirect_sending_is_disabled,
  Boolean $ensure_source_routed_packets_are_not_accepted,
  Boolean $ensure_icmp_redirects_are_not_accepted,
  Boolean $ensure_secure_icmp_redirects_are_not_accepted,
  Boolean $ensure_suspicious_packets_are_logged,
  Boolean $ensure_broadcast_icmp_requests_are_ignored,
  Boolean $ensure_bogus_icmp_responses_are_ignored,
  Boolean $ensure_reverse_path_filtering_is_enabled,
  Boolean $ensure_tcp_syn_cookies_is_enabled,
  Boolean $ensure_ipv6_router_advertisements_are_not_accepted,
  Boolean $ensure_ipv6_redirects_are_not_accepted,
  Boolean $ensure_ipv6_is_disabled,
  Boolean $ensure_tcp_wrappers_is_installed,
  Boolean $ensure__etc_hosts_allow_is_configured,
  Boolean $ensure__etc_hosts_deny_is_configured,
  Boolean $ensure_dccp_is_disabled,
  Boolean $ensure_sctp_is_disabled,
  Boolean $ensure_rds_is_disabled,
  Boolean $ensure_tipc_is_disabled,
  Boolean $ensure_iptables_is_installed,
  Boolean $ensure_default_deny_firewall_policy,
  Boolean $ensure_loopback_traffic_is_configured,
  Boolean $ensure_outbound_and_established_connections_are_configured,
  Boolean $ensure_wireless_interfaces_are_disabled,
  Boolean $ensure_audit_log_storage_size_is_configured,
  Boolean $ensure_system_is_disabled_when_audit_logs_are_full,
  Boolean $ensure_audit_logs_are_not_automatically_deleted,
  Boolean $ensure_auditd_service_is_enabled,
  Boolean $ensure_auditing_for_processes_that_start_prior_to_auditd_is_enabled,
  Boolean $ensure_events_that_modify_date_and_time_information_are_collected,
  Boolean $ensure_events_that_modify_user_group_information_are_collected,
  Boolean $ensure_events_that_modify_the_systems_network_environment_are_collected,
  Boolean $ensure_events_that_modify_the_systems_mandatory_access_controls_are_collected,
  Boolean $ensure_login_and_logout_events_are_collected,
  Boolean $ensure_session_initiation_information_is_collected,
  Boolean $ensure_discretionary_access_control_permission_modification_events_are_collected,
  Boolean $ensure_unsuccessful_unauthorized_file_access_attempts_are_collected,
  Boolean $ensure_use_of_privileged_commands_is_collected,
  Boolean $ensure_successful_file_system_mounts_are_collected,
  Boolean $ensure_file_deletion_events_by_users_are_collected,
  Boolean $ensure_changes_to_system_administration_scope_sudoers_is_collected,
  Boolean $ensure_system_administrator_actions_sudolog_are_collected,
  Boolean $ensure_kernel_module_loading_and_unloading_is_collected,
  Boolean $ensure_the_audit_configuration_is_immutable,
  Boolean $ensure_rsyslog_service_is_enabled,
  Boolean $ensure_logging_is_configured,
  Boolean $ensure_rsyslog_default_file_permissions_configured,
  Boolean $ensure_rsyslog_is_configured_to_send_logs_to_a_remote_log_host,
  Boolean $ensure_remote_rsyslog_messages_are_only_accepted_on_designated_log_hosts,
  Boolean $ensure_syslog_ng_service_is_enabled,
  Boolean $ensure_syslog_ng_default_file_permissions_configured,
  Boolean $ensure_syslog_ng_is_configured_to_send_logs_to_a_remote_log_host,
  Boolean $ensure_remote_syslog_ng_messages_are_only_accepted_on_designated_log_hosts,
  Boolean $ensure_rsyslog_or_syslog_ng_is_installed,
  Boolean $ensure_permissions_on_all_logfiles_are_configured,
  Boolean $ensure_logrotate_is_configured,
  Boolean $ensure_cron_daemon_is_enabled,
  Boolean $ensure_permissions_on__etc_crontab_are_configured,
  Boolean $ensure_permissions_on__etc_cron_hourly_are_configured,
  Boolean $ensure_permissions_on__etc_cron_daily_are_configured,
  Boolean $ensure_permissions_on__etc_cron_weekly_are_configured,
  Boolean $ensure_permissions_on__etc_cron_monthly_are_configured,
  Boolean $ensure_permissions_on__etc_cron_d_are_configured,
  Boolean $ensure_at_cron_is_restricted_to_authorized_users,
  Boolean $ensure_permissions_on__etc_ssh_sshd_config_are_configured,
  Boolean $ensure_ssh_protocol_is_set_to_2,
  Boolean $ensure_ssh_loglevel_is_set_to_info,
  Boolean $ensure_ssh_x11_forwarding_is_disabled,
  Boolean $ensure_ssh_maxauthtries_is_set_to_4_or_less,
  Boolean $ensure_ssh_ignorerhosts_is_enabled,
  Boolean $ensure_ssh_hostbasedauthentication_is_disabled,
  Boolean $ensure_ssh_root_login_is_disabled,
  Boolean $ensure_ssh_permitemptypasswords_is_disabled,
  Boolean $ensure_ssh_permituserenvironment_is_disabled,
  Boolean $ensure_only_approved_ciphers_are_used,
  Boolean $ensure_only_approved_mac_algorithms_are_used,
  Boolean $ensure_ssh_idle_timeout_interval_is_configured,
  Boolean $ensure_ssh_logingracetime_is_set_to_one_minute_or_less,
  Boolean $ensure_ssh_access_is_limited,
  Boolean $ensure_ssh_warning_banner_is_configured,
  Boolean $ensure_password_creation_requirements_are_configured,
  Boolean $ensure_lockout_for_failed_password_attempts_is_configured,
  Boolean $ensure_password_reuse_is_limited,
  Boolean $ensure_password_hashing_algorithm_is_sha_512,
  Boolean $ensure_password_expiration_is_90_days_or_less,
  Boolean $ensure_minimum_days_between_password_changes_is_7_or_more,
  Boolean $ensure_password_expiration_warning_days_is_7_or_more,
  Boolean $ensure_inactive_password_lock_is_30_days_or_less,
  Boolean $ensure_system_accounts_are_non_login,
  Boolean $ensure_default_group_for_the_root_account_is_gid_0,
  Boolean $ensure_default_user_umask_is_027_or_more_restrictive,
  Boolean $ensure_root_login_is_restricted_to_system_console,
  Boolean $ensure_access_to_the_su_command_is_restricted,
  Boolean $ensure_permissions_on__etc_passwd_are_configured,
  Boolean $ensure_permissions_on__etc_shadow_are_configured,
  Boolean $ensure_permissions_on__etc_group_are_configured,
  Boolean $ensure_permissions_on__etc_gshadow_are_configured,
  Boolean $ensure_permissions_on__etc_passwd__are_configured,
  Boolean $ensure_permissions_on__etc_shadow__are_configured,
  Boolean $ensure_permissions_on__etc_group__are_configured,
  Boolean $ensure_permissions_on__etc_gshadow__are_configured,
  Boolean $ensure_no_world_writable_files_exist,
  Boolean $ensure_no_unowned_files_or_directories_exist,
  Boolean $ensure_no_ungrouped_files_or_directories_exist,
  Boolean $ensure_password_fields_are_not_empty,
  Boolean $ensure_no_legacy_plus_entries_exist_in__etc_passwd,
  Boolean $ensure_no_legacy_plus_entries_exist_in__etc_shadow,
  Boolean $ensure_no_legacy_plus_entries_exist_in__etc_group,
  Boolean $ensure_root_is_the_only_uid_0_account,
  Boolean $ensure_root_path_integrity,
  Boolean $ensure_all_users_home_directories_exist,
  Boolean $ensure_users_home_directories_permissions_are_750_or_more_restrictive,
  Boolean $ensure_users_own_their_home_directories,
  Boolean $ensure_users_dot_files_are_not_group_or_world_writable,
  Boolean $ensure_no_users_have_forward_files,
  Boolean $ensure_no_users_have_netrc_files,
  Boolean $ensure_users_netrc_files_are_not_group_or_world_accessible,
  Boolean $ensure_no_users_have_rhosts_files,
  Boolean $ensure_all_groups_in__etc_passwd_exist_in__etc_group,
  Boolean $ensure_no_duplicate_uids_exist,
  Boolean $ensure_no_duplicate_gids_exist,
  Boolean $ensure_no_duplicate_user_names_exist,
  Boolean $ensure_no_duplicate_group_names_exist,
  # Hash $managed_files,
  # Hash $kernel_module_options,
  # Hash $kernel_module_installs,
  # Hash $managed_packages,
  # Hash $sshd_configs,
  # Hash $kernel_parameters,
  # Hash $managed_services,
  # Hash $file_line_rules,
  # Hash $augeas_rules,
  # Hash $limits,
) {
  Firewall {
    require => undef,
  }

  resources { 'firewall':
    purge => true,
  }

  # Ensure time synchronization is in use
  class { '::ntp':
    servers => [ 'ntp1.corp.com', 'ntp2.corp.com' ],
  }

  class { '::harden_centos_os::install': }
  -> class { '::harden_centos_os::configure': }
  ~> class { '::harden_centos_os::run': }
  -> Class['::harden_centos_os']

  # class { '::harden_centos_os::kernel_parameters': }
  # ~> class { '::harden_centos_os::kernel_parameters_flush': }
  # -> Class['::harden_centos_os']

  class { '::harden_centos_os::pre_fw': }
  -> class { '::harden_centos_os::post_fw': }
  -> Class['::harden_centos_os']
}
