const char* version = PACKAGE_VERSION;

void
plugin_register (void)
{
  proto_register_corosync_totemnet();
  proto_register_corosync_totemsrp();
  proto_register_corosync_totempg();

  proto_register_openais_a();
  proto_register_openais_clm();
  proto_register_openais_cman();
  proto_register_openais_cpg();
  proto_register_openais_evt();
  proto_register_openais_ckpt();
  proto_register_openais_flowcontrol();
  proto_register_openais_sync(); 

  proto_register_corosync_syncv2(); 

  /* proto_register_ccsd();  */
  proto_register_clumond(); 
  proto_register_clvmd(); 
  proto_register_groupd(); 
  proto_register_rgmanager(); 

  proto_register_rhcs_fenced();
  proto_register_dlm_controld();
  proto_register_gfs_controld();



  proto_reg_handoff_corosync_totemnet();
  proto_reg_handoff_corosync_totemsrp();
  proto_reg_handoff_corosync_totempg();

  proto_reg_handoff_openais_a();
  proto_reg_handoff_openais_clm();
  proto_reg_handoff_openais_cman();
  proto_reg_handoff_openais_cpg();
  proto_reg_handoff_openais_evt();
  proto_reg_handoff_openais_ckpt();
  proto_reg_handoff_openais_flowcontrol();
  proto_reg_handoff_openais_sync();

  proto_reg_handoff_corosync_syncv2();

  /* proto_reg_handoff_ccsd();  */
  proto_reg_handoff_clumond(); 
  proto_reg_handoff_clvmd(); 
  proto_reg_handoff_groupd(); 
  proto_reg_handoff_rgmanager(); 

  
  proto_reg_handoff_rhcs_fenced();
  proto_reg_handoff_dlm_controld();
  proto_reg_handoff_gfs_controld();
}
