var aio_init_addr = libkernel_base + 126912;
var fpathconf_addr = libkernel_base + 126944;
var dmem_container_addr = libkernel_base + 126976;
var evf_clear_addr = libkernel_base + 127008;
var kqueue_addr = libkernel_base + 127040;
var kevent_addr = libkernel_base + 127072;
var futimes_addr = libkernel_base + 127104;
var open_addr = libkernel_base + 127136;
var thr_self_addr = libkernel_base + 127168;
var mkdir_addr = libkernel_base + 127200;
var pipe_addr = libkernel_base + 127232;
var stat_addr = libkernel_base + 127280;
var write_addr = libkernel_base + 127312;
var evf_cancel_addr = libkernel_base + 127344;
var ktimer_delete_addr = libkernel_base + 127376;
var setregid_addr = libkernel_base + 127408;
var jitshm_create_addr = libkernel_base + 127440;
var sigwait_addr = libkernel_base + 127472;
var fdatasync_addr = libkernel_base + 127504;
var sigtimedwait_addr = libkernel_base + 127536;
var get_gpo_addr = libkernel_base + 127568;
var sched_setscheduler_addr = libkernel_base + 127600;
var osem_open_addr = libkernel_base + 127632;
var dynlib_get_info_addr = libkernel_base + 127664;
var osem_post_addr = libkernel_base + 127712;
var blockpool_move_addr = libkernel_base + 127744;
var issetugid_addr = libkernel_base + 127776;
var getdents_addr = libkernel_base + 127808;
var rtprio_thread_addr = libkernel_base + 127840;
var evf_delete_addr = libkernel_base + 127872;
var _umtx_op_addr = libkernel_base + 127904;
var access_addr = libkernel_base + 127936;
var reboot_addr = libkernel_base + 127968;
var sigaltstack_addr = libkernel_base + 128e3;
var getcontext_addr = libkernel_base + 128036;
var munmap_addr = libkernel_base + 128080;
var setuid_addr = libkernel_base + 128112;
var evf_trywait_addr = libkernel_base + 128144;
var setcontext_addr = libkernel_base + 128176;
var dynlib_get_list_addr = libkernel_base + 128208;
var setsid_addr = libkernel_base + 128240;
var fstatfs_addr = libkernel_base + 128272;
var aio_multi_wait_addr = libkernel_base + 128304;
var accept_addr = libkernel_base + 128336;
var set_phys_fmem_limit_addr = libkernel_base + 128368;
var thr_get_name_addr = libkernel_base + 128400;
var get_page_table_stats_addr = libkernel_base + 128432;
var sigsuspend_addr = libkernel_base + 128464;
var truncate_addr = libkernel_base + 128496;
var fsync_addr = libkernel_base + 128528;
var execve_addr = libkernel_base + 128573;
var evf_open_addr = libkernel_base + 128608;
var netabort_addr = libkernel_base + 128640;
var blockpool_unmap_addr = libkernel_base + 128672;
var osem_create_addr = libkernel_base + 128704;
var getlogin_addr = libkernel_base + 128736;
var mincore_addr = libkernel_base + 128768;
var shutdown_addr = libkernel_base + 128800;
var profil_addr = libkernel_base + 128832;
var preadv_addr = libkernel_base + 128864;
var geteuid_addr = libkernel_base + 128896;
var set_chicken_switches_addr = libkernel_base + 128928;
var sigqueue_addr = libkernel_base + 128960;
var aio_multi_poll_addr = libkernel_base + 128992;
var get_self_auth_info_addr = libkernel_base + 129024;
var opmc_enable_addr = libkernel_base + 129056;
var aio_multi_delete_addr = libkernel_base + 129088;
var rfork_addr = libkernel_base + 129129;
var sys_exit_addr = libkernel_base + 129162;
var blockpool_batch_addr = libkernel_base + 129200;
var sigpending_addr = libkernel_base + 129232;
var ktimer_gettime_addr = libkernel_base + 129264;
var opmc_set_ctr_addr = libkernel_base + 129296;
var ksem_wait_addr = libkernel_base + 129328;
var sched_getparam_addr = libkernel_base + 129360;
var swapcontext_addr = libkernel_base + 129392;
var opmc_get_ctr_addr = libkernel_base + 129424;
var budget_get_ptype_addr = libkernel_base + 129456;
var msync_addr = libkernel_base + 129488;
var sigwaitinfo_addr = libkernel_base + 129520;
var lstat_addr = libkernel_base + 129552;
var test_debug_rwmem_addr = libkernel_base + 129584;
var evf_create_addr = libkernel_base + 129616;
var madvise_addr = libkernel_base + 129648;
var cpuset_getaffinity_addr = libkernel_base + 129680;
var evf_set_addr = libkernel_base + 129712;
var setlogin_addr = libkernel_base + 129744;
var ksem_init_addr = libkernel_base + 129792;
var opmc_disable_addr = libkernel_base + 129824;
var namedobj_delete_addr = libkernel_base + 129856;
var gettimeofday_addr = libkernel_base + 129888;
var read_addr = libkernel_base + 129920;
var thr_get_ucontext_addr = libkernel_base + 129952;
var batch_map_addr = libkernel_base + 129984;
var sysarch_addr = libkernel_base + 130016;
var utc_to_localtime_addr = libkernel_base + 130048;
var evf_close_addr = libkernel_base + 130080;
var setrlimit_addr = libkernel_base + 130112;
var getpeername_addr = libkernel_base + 130144;
var aio_get_data_addr = libkernel_base + 130176;
var lseek_addr = libkernel_base + 130208;
var connect_addr = libkernel_base + 130240;
var recvfrom_addr = libkernel_base + 130272;
var getrlimit_addr = libkernel_base + 130304;
var dynlib_get_info_for_libdbg_addr = libkernel_base + 130336;
var thr_suspend_ucontext_addr = libkernel_base + 130368;
var _umtx_op_addr = libkernel_base + 130400;
var kill_addr = libkernel_base + 130416;
var dynlib_process_needed_and_relocate_addr = libkernel_base + 130448;
var getsockname_addr = libkernel_base + 130480;
var osem_trywait_addr = libkernel_base + 130512;
var execve_addr = libkernel_base + 130544;
var flock_addr = libkernel_base + 130576;
var sigreturn_addr = libkernel_base + 130608;
var query_memory_protection_addr = libkernel_base + 130640;
var pwrite_addr = libkernel_base + 130672;
var get_map_statistics_addr = libkernel_base + 130704;
var ksem_getvalue_addr = libkernel_base + 130736;
var sendfile_addr = libkernel_base + 130768;
var socketex_addr = libkernel_base + 130800;
var unlink_addr = libkernel_base + 130832;
var thr_resume_ucontext_addr = libkernel_base + 130864;
var dl_get_list_addr = libkernel_base + 130896;
var cpuset_setaffinity_addr = libkernel_base + 130928;
var clock_gettime_addr = libkernel_base + 130960;
var thr_kill2_addr = libkernel_base + 130992;
var set_timezone_info_addr = libkernel_base + 131024;
var select_addr = libkernel_base + 131056;
var pselect_addr = libkernel_base + 131088;
var sync_addr = libkernel_base + 131120;
var socketpair_addr = libkernel_base + 131152;
var get_kernel_mem_statistics_addr = libkernel_base + 131184;
var virtual_query_all_addr = libkernel_base + 131216;
var physhm_open_addr = libkernel_base + 131248;
var getuid_addr = libkernel_base + 131280;
var revoke_addr = libkernel_base + 131312;
var sigprocmask_addr = libkernel_base + 131347;
var setegid_addr = libkernel_base + 131488;
var cpuset_getid_addr = libkernel_base + 131520;
var evf_wait_addr = libkernel_base + 131552;
var sched_get_priority_max_addr = libkernel_base + 131584;
var sigaction_addr = libkernel_base + 131616;
var ipmimgr_call_addr = libkernel_base + 131648;
var aio_submit_cmd_addr = libkernel_base + 131680;
var free_stack_addr = libkernel_base + 131712;
var settimeofday_addr = libkernel_base + 131744;
var recvmsg_addr = libkernel_base + 131776;
var aio_submit_addr = libkernel_base + 131808;
var setgroups_addr = libkernel_base + 131840;
var aio_multi_cancel_addr = libkernel_base + 131872;
var nanosleep_addr = libkernel_base + 131904;
var blockpool_map_addr = libkernel_base + 131936;
var thr_create_addr = libkernel_base + 131968;
var munlockall_addr = libkernel_base + 132e3;
var dynlib_get_info_ex_addr = libkernel_base + 132032;
var pwritev_addr = libkernel_base + 132064;
var mname_addr = libkernel_base + 132096;
var regmgr_call_addr = libkernel_base + 132128;
var getgroups_addr = libkernel_base + 132160;
var osem_close_addr = libkernel_base + 132192;
var osem_delete_addr = libkernel_base + 132224;
var dynlib_get_obj_member_addr = libkernel_base + 132256;
var debug_init_addr = libkernel_base + 132288;
var mmap_dmem_addr = libkernel_base + 132320;
var kldunloadf_addr = libkernel_base + 132352;
var mprotect_addr = libkernel_base + 132384;
var ksem_trywait_addr = libkernel_base + 132592;
var ksem_close_addr = libkernel_base + 132624;
var sched_rr_get_interval_addr = libkernel_base + 132656;
var getitimer_addr = libkernel_base + 132688;
var getpid_addr = libkernel_base + 132720;
var netgetsockinfo_addr = libkernel_base + 132752;
var get_cpu_usage_all_addr = libkernel_base + 132784;
var eport_delete_addr = libkernel_base + 132816;
var randomized_path_addr = libkernel_base + 132848;
var jitshm_alias_addr = libkernel_base + 132880;
var seteuid_addr = libkernel_base + 132912;
var set_uevt_addr = libkernel_base + 132944;
var clock_getres_addr = libkernel_base + 132976;
var setitimer_addr = libkernel_base + 133008;
var thr_exit_addr = libkernel_base + 133040;
var sandbox_path_addr = libkernel_base + 133072;
var thr_kill_addr = libkernel_base + 133104;
var sys_exit_addr = libkernel_base + 133136;
var dup2_addr = libkernel_base + 133168;
var utimes_addr = libkernel_base + 133200;
var pread_addr = libkernel_base + 133232;
var dl_get_info_addr = libkernel_base + 133264;
var ktimer_settime_addr = libkernel_base + 133296;
var sched_setparam_addr = libkernel_base + 133328;
var aio_create_addr = libkernel_base + 133360;
var osem_wait_addr = libkernel_base + 133392;
var dynlib_get_list_for_libdbg_addr = libkernel_base + 133424;
var get_proc_type_info_addr = libkernel_base + 133456;
var getgid_addr = libkernel_base + 133488;
var fstat_addr = libkernel_base + 133520;
var fork_addr = libkernel_base + 133552;
var namedobj_create_addr = libkernel_base + 133584;
var opmc_set_ctl_addr = libkernel_base + 133616;
var get_resident_count_addr = libkernel_base + 133648;
var getdirentries_addr = libkernel_base + 133680;
var getrusage_addr = libkernel_base + 133712;
var setreuid_addr = libkernel_base + 133744;
var wait4_addr = libkernel_base + 133776;
var __sysctl_addr = libkernel_base + 133808;
var bind_addr = libkernel_base + 133840;
var sched_yield_addr = libkernel_base + 133872;
var dl_get_metadata_addr = libkernel_base + 133904;
var get_resident_fmem_count_addr = libkernel_base + 133936;
var setsockopt_addr = libkernel_base + 133968;
var dynlib_load_prx_addr = libkernel_base + 134e3;
var getpriority_addr = libkernel_base + 134032;
var get_phys_page_size_addr = libkernel_base + 134064;
var opmc_set_hw_addr = libkernel_base + 134096;
var dynlib_do_copy_relocations_addr = libkernel_base + 134128;
var netcontrol_addr = libkernel_base + 134160;
var ksem_post_addr = libkernel_base + 134192;
var netgetiflist_addr = libkernel_base + 134224;
var chmod_addr = libkernel_base + 134256;
var aio_suspend_addr = libkernel_base + 134288;
var ksem_timedwait_addr = libkernel_base + 134320;
var dynlib_dlsym_addr = libkernel_base + 134352;
var get_paging_stats_of_all_objects_addr = libkernel_base + 134384;
var osem_cancel_addr = libkernel_base + 134416;
var writev_addr = libkernel_base + 134448;
var ktimer_getoverrun_addr = libkernel_base + 134480;
var rmdir_addr = libkernel_base + 134512;
var sched_get_priority_min_addr = libkernel_base + 134544;
var dynlib_unload_prx_addr = libkernel_base + 134576;
var thr_set_name_addr = libkernel_base + 134608;
var mlockall_addr = libkernel_base + 134640;
var openat_addr = libkernel_base + 134672;
var eport_open_addr = libkernel_base + 134704;
var sigprocmask_addr = libkernel_base + 134736;
var chdir_addr = libkernel_base + 134768;
var physhm_unlink_addr = libkernel_base + 134800;
var mtypeprotect_addr = libkernel_base + 134832;
var thr_wake_addr = libkernel_base + 134864;
var blockpool_open_addr = libkernel_base + 134896;
var thr_new_addr = libkernel_base + 134928;
var munlock_addr = libkernel_base + 134960;
var fchflags_addr = libkernel_base + 134992;
var ftruncate_addr = libkernel_base + 135024;
var rename_addr = libkernel_base + 135056;
var poll_addr = libkernel_base + 135088;
var eport_trigger_addr = libkernel_base + 135120;
var getsid_addr = libkernel_base + 135152;
var virtual_query_addr = libkernel_base + 135184;
var fchmod_addr = libkernel_base + 135216;
var _umtx_unlock_addr = libkernel_base + 135248;
var mmap_addr = libkernel_base + 135280;
var ktimer_create_addr = libkernel_base + 135312;
var dup_addr = libkernel_base + 135344;
var sendmsg_addr = libkernel_base + 135376;
var close_addr = libkernel_base + 135408;
var is_development_mode_addr = libkernel_base + 135440;
var getegid_addr = libkernel_base + 135472;
var get_vm_map_timestamp_addr = libkernel_base + 135504;
var dynlib_get_proc_param_addr = libkernel_base + 135536;
var fcntl_addr = libkernel_base + 135568;
var getppid_addr = libkernel_base + 135600;
var readv_addr = libkernel_base + 135632;
var rdup_addr = libkernel_base + 135664;
var listen_addr = libkernel_base + 135696;
var app_state_change_addr = libkernel_base + 135728;
var set_gpo_addr = libkernel_base + 135760;
var ksem_unlink_addr = libkernel_base + 135792;
var get_cpu_usage_proc_addr = libkernel_base + 135824;
var shm_unlink_addr = libkernel_base + 135856;
var reserve_2mb_page_addr = libkernel_base + 135888;
var dynlib_get_info2_addr = libkernel_base + 135920;
var mlock_addr = libkernel_base + 135952;
var workaround8849_addr = libkernel_base + 135984;
var get_sdk_compiled_version_addr = libkernel_base + 136016;
var clock_settime_addr = libkernel_base + 136048;
var ksem_destroy_addr = libkernel_base + 136080;
var ksem_open_addr = libkernel_base + 136112;
var thr_set_ucontext_addr = libkernel_base + 136144;
var get_bio_usage_all_addr = libkernel_base + 136176;
var getdtablesize_addr = libkernel_base + 136208;
var chflags_addr = libkernel_base + 136240;
var shm_open_addr = libkernel_base + 136272;
var eport_close_addr = libkernel_base + 136304;
var dynlib_get_list2_addr = libkernel_base + 136336;
var socketclose_addr = libkernel_base + 136368;
var sched_getscheduler_addr = libkernel_base + 136400;
var pathconf_addr = libkernel_base + 136432;
var localtime_to_utc_addr = libkernel_base + 136464;
var setpriority_addr = libkernel_base + 136496;
var cpumode_yield_addr = libkernel_base + 136528;
var process_terminate_addr = libkernel_base + 136560;
var ioctl_addr = libkernel_base + 136592;
var opmc_get_hw_addr = libkernel_base + 136624;
var eport_create_addr = libkernel_base + 136656;
var socket_addr = libkernel_base + 136688;
var _umtx_lock_addr = libkernel_base + 136720;
var thr_suspend_addr = libkernel_base + 136752;
var is_in_sandbox_addr = libkernel_base + 136784;
var get_authinfo_addr = libkernel_base + 136816;
var mdbg_service_addr = libkernel_base + 136848;
var getsockopt_addr = libkernel_base + 136880;
var get_paging_stats_of_all_threads_addr = libkernel_base + 136912;
var adjtime_addr = libkernel_base + 136944;
var kqueueex_addr = libkernel_base + 136976;
var uuidgen_addr = libkernel_base + 137008;
var set_vm_container_addr = libkernel_base + 137040;
var sendto_addr = libkernel_base + 137072;
