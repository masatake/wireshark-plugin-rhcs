const char* version = PACKAGE_VERSION;

#define DECL(f) void proto_register_##f(void); \
             void proto_reg_handoff_##f(void)

DECL(corosync_totemnet);
DECL(corosync_totemsrp);
DECL(corosync_totempg);

DECL(openais_a);
DECL(openais_clm);
DECL(openais_cman);
DECL(openais_cpg);
DECL(openais_evt);
DECL(openais_ckpt);
DECL(openais_flowcontrol);
DECL(openais_sync); 

DECL(corosync_syncv2); 

/* DECL(ccsd);  */
DECL(clumond); 
DECL(clvmd); 
DECL(groupd); 
DECL(rgmanager); 

DECL(rhcs_fenced);
DECL(dlm_controld);
DECL(gfs_controld);


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
