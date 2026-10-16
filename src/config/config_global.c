#define MODULE_LOG_PREFIX "conf"
#include "config_internal.h"
void cfg_default_runtime(S_CONFIG*c)
{
    memset(c->readers,0,sizeof(c->readers));
    c->nreaders=0;
    c->accounts=NULL;
    c->naccounts=0;
    c->sock_timeout=30;
    c->server_keepalive=20;
    c->server_keepalive_misses=3;
    c->ecm_log=1;
    c->scheduled_restart_enabled=0;
    c->scheduled_restart_minutes=0;
    c->cccam_port=0;
    c->cccam_bindaddr[0]='\0';
    c->cs378x_port=0;
    c->cs378x_bindaddr[0]='\0';
    c->camd35_port=0;
    c->camd35_bindaddr[0]='\0';
    c->newcamd_port=0;
    c->newcamd_bindaddr[0]='\0';
    memset(c->newcamd_key,0,sizeof(c->newcamd_key));
    c->newcamd_keepalive=0;
    c->newcamd_mgclient=0;
    c->webif_enabled=1;
    c->webif_port=8585;
    c->webif_refresh=1;
    tcmg_strlcpy(c->webif_bindaddr,"127.0.0.1",sizeof(c->webif_bindaddr));
    c->failban_enabled=1;
    c->failban_max_fails=BAN_MAX_FAILS;
    c->failban_ban_secs=BAN_SECS;
    c->seller_name[0]='\0';
    tcmg_strlcpy(c->seller_type,"cccam",sizeof(c->seller_type));
    c->seller_host[0]='\0';
    c->seller_port=0;
    c->dvbapi_enabled=0;
    tcmg_strlcpy(c->dvbapi_user,"dvbapi",sizeof(c->dvbapi_user));
    tcmg_strlcpy(c->dvbapi_socket,"/tmp/camd.socket",sizeof(c->dvbapi_socket));
    tcmg_strlcpy(c->dvbapi_boxtype,"auto",sizeof(c->dvbapi_boxtype));
    c->dvbapi_delay_ms=0;
    c->dvbapi_max_services=8;
    c->dvbapi_pmt_mode=0;
    c->dvbapi_listen_port=0;
    tcmg_strlcpy(c->dvbapi_serverip,"127.0.0.1",sizeof(c->dvbapi_serverip));
    c->lb_mode=0;
    c->lb_nbest_readers=1;
}
E_CFG_CB_RESULT cfg_global_cb(const char*sec,const S_KV*k,void*ctx,char*err,size_t esz)
{
    S_CONFIG*c=ctx;
    int32_t v;
    bool b;
    if(!*sec){snprintf(err,esz,"line %d: setting outside a section",k->line);return CFG_CB_INVALID;}
    if(!strcasecmp(sec,"global")){
        if(!strcasecmp(k->key,"scheduled_restart")){if(!cfg_parse_bool(k->value,&b))goto bad;c->scheduled_restart_enabled=b;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"scheduled_restart_time")){int hh=-1,mm=-1;if(sscanf(k->value,"%d:%d",&hh,&mm)!=2||hh<0||hh>23||mm<0||mm>59||strlen(k->value)!=5||k->value[2]!=':')goto bad;c->scheduled_restart_minutes=(int16_t)(hh*60+mm);return CFG_CB_OK;}
        if(!strcasecmp(k->key,"socket_timeout")){if(!cfg_parse_i32_range(k->value,1,600,&v))goto bad;c->sock_timeout=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"server_keepalive")){if(!cfg_parse_i32_range(k->value,0,3600,&v))goto bad;c->server_keepalive=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"server_keepalive_misses")){if(!cfg_parse_i32_range(k->value,1,20,&v))goto bad;c->server_keepalive_misses=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"ecm_log")){if(!cfg_parse_bool(k->value,&b))goto bad;c->ecm_log=b;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"lb_mode")){if(!cfg_parse_i32_range(k->value,0,3,&v))goto bad;c->lb_mode=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"lb_nbest_readers")){if(!cfg_parse_i32_range(k->value,1,16,&v))goto bad;c->lb_nbest_readers=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"logfile")){if(strlen(k->value)>=sizeof(c->logfile))goto bad;tcmg_strlcpy(c->logfile,k->value,sizeof(c->logfile));return CFG_CB_OK;}
        if(!strcasecmp(k->key,"usrfile")){if(strlen(k->value)>=sizeof(c->usrfile))goto bad;tcmg_strlcpy(c->usrfile,k->value,sizeof(c->usrfile));return CFG_CB_OK;}
        goto unknown;
    }
    if(!strcasecmp(sec,"webif")){
        if(!strcasecmp(k->key,"enabled")){if(!cfg_parse_bool(k->value,&b))goto bad;c->webif_enabled=b;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"port")){if(!cfg_parse_i32_range(k->value,0,65535,&v))goto bad;c->webif_port=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"refresh")){if(!cfg_parse_i32_range(k->value,0,3600,&v))goto bad;c->webif_refresh=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"user")){if(strlen(k->value)>=sizeof(c->webif_user))goto bad;tcmg_strlcpy(c->webif_user,k->value,sizeof(c->webif_user));return CFG_CB_OK;}
        if(!strcasecmp(k->key,"password")){if(strlen(k->value)>=sizeof(c->webif_pass))goto bad;tcmg_strlcpy(c->webif_pass,k->value,sizeof(c->webif_pass));return CFG_CB_OK;}
        if(!strcasecmp(k->key,"bindaddr")){if(k->value[0]&&!cfg_parse_bindaddr(k->value))goto bad;tcmg_strlcpy(c->webif_bindaddr,k->value,sizeof(c->webif_bindaddr));return CFG_CB_OK;}
        goto unknown;
    }
    if(!strcasecmp(sec,"newcamd")){
        if(!strcasecmp(k->key,"port")){if(!cfg_parse_i32_range(k->value,0,65535,&v))goto bad;c->newcamd_port=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"bindaddr")){if(k->value[0]&&!cfg_parse_bindaddr(k->value))goto bad;tcmg_strlcpy(c->newcamd_bindaddr,k->value,sizeof(c->newcamd_bindaddr));return CFG_CB_OK;}
        if(!strcasecmp(k->key,"key")){if(!cfg_parse_hex_bytes(k->value,c->newcamd_key,14))goto bad;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"keepalive")){if(!cfg_parse_bool(k->value,&b))goto bad;c->newcamd_keepalive=b;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"mode")){if(strcasecmp(k->value,"auto")&&strcasecmp(k->value,"newcamd")&&strcasecmp(k->value,"mgcamd"))goto bad;c->newcamd_mgclient=!strcasecmp(k->value,"mgcamd");return CFG_CB_OK;}
        goto unknown;
    }
    if(!strcasecmp(sec,"cccam")){
        if(!strcasecmp(k->key,"port")){if(!cfg_parse_i32_range(k->value,0,65535,&v))goto bad;c->cccam_port=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"bindaddr")){if(k->value[0]&&!cfg_parse_bindaddr(k->value))goto bad;tcmg_strlcpy(c->cccam_bindaddr,k->value,sizeof(c->cccam_bindaddr));return CFG_CB_OK;}
        goto unknown;
    }
    if(!strcasecmp(sec,"cs378x")){
        if(!strcasecmp(k->key,"port")){if(!cfg_parse_i32_range(k->value,0,65535,&v))goto bad;c->cs378x_port=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"bindaddr")){if(k->value[0]&&!cfg_parse_bindaddr(k->value))goto bad;tcmg_strlcpy(c->cs378x_bindaddr,k->value,sizeof(c->cs378x_bindaddr));return CFG_CB_OK;}
        goto unknown;
    }
    if(!strcasecmp(sec,"camd35")){
        if(!strcasecmp(k->key,"port")){if(!cfg_parse_i32_range(k->value,0,65535,&v))goto bad;c->camd35_port=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"bindaddr")){if(k->value[0]&&!cfg_parse_bindaddr(k->value))goto bad;tcmg_strlcpy(c->camd35_bindaddr,k->value,sizeof(c->camd35_bindaddr));return CFG_CB_OK;}
        goto unknown;
    }
    if(!strcasecmp(sec,"failban")){
        if(!strcasecmp(k->key,"enabled")){if(!cfg_parse_bool(k->value,&b))goto bad;c->failban_enabled=b;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"allowlist")){if(strlen(k->value)>=sizeof(c->failban_allowlist))goto bad;tcmg_strlcpy(c->failban_allowlist,k->value,sizeof(c->failban_allowlist));return CFG_CB_OK;}
        if(!strcasecmp(k->key,"max_fails")){if(!cfg_parse_i32_range(k->value,1,1000,&v))goto bad;c->failban_max_fails=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"ban_secs")){if(!cfg_parse_i32_range(k->value,10,604800,&v))goto bad;c->failban_ban_secs=v;return CFG_CB_OK;}
        goto unknown;
    }
    if(!strcasecmp(sec,"seller")){
        if(!strcasecmp(k->key,"name")){if(strlen(k->value)>=sizeof(c->seller_name))goto bad;tcmg_strlcpy(c->seller_name,k->value,sizeof(c->seller_name));return CFG_CB_OK;}
        if(!strcasecmp(k->key,"type")){
            const char*t=k->value;
            if(strcasecmp(t,"cccam")&&strcasecmp(t,"newcamd")&&strcasecmp(t,"cs378x")&&strcasecmp(t,"camd35"))goto bad;
            for(size_t i=0;i<sizeof(c->seller_type)-1&&t[i];i++)c->seller_type[i]=(char)tolower((unsigned char)t[i]),c->seller_type[i+1]='\0';
            return CFG_CB_OK;
        }
        if(!strcasecmp(k->key,"host")){if(strlen(k->value)>=sizeof(c->seller_host))goto bad;tcmg_strlcpy(c->seller_host,k->value,sizeof(c->seller_host));return CFG_CB_OK;}
        if(!strcasecmp(k->key,"port")){if(!cfg_parse_i32_range(k->value,0,65535,&v))goto bad;c->seller_port=v;return CFG_CB_OK;}
        goto unknown;
    }
    if(!strcasecmp(sec,"dvbapi")){
        if(!strcasecmp(k->key,"enabled")){if(!cfg_parse_bool(k->value,&b))goto bad;c->dvbapi_enabled=b;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"user")){if(!k->value[0]||strlen(k->value)>=sizeof(c->dvbapi_user))goto bad;tcmg_strlcpy(c->dvbapi_user,k->value,sizeof(c->dvbapi_user));return CFG_CB_OK;}
        if(!strcasecmp(k->key,"socket")){if(!k->value[0]||k->value[0]!='/'||strlen(k->value)>=sizeof(c->dvbapi_socket))goto bad;tcmg_strlcpy(c->dvbapi_socket,k->value,sizeof(c->dvbapi_socket));return CFG_CB_OK;}
        if(!strcasecmp(k->key,"boxtype")){
            const char*t=k->value;
            if(strcasecmp(t,"auto")&&strcasecmp(t,"dreambox")&&strcasecmp(t,"duckbox")&&strcasecmp(t,"ufs910"))goto bad;
            for(size_t i=0;i<sizeof(c->dvbapi_boxtype)-1&&t[i];i++)c->dvbapi_boxtype[i]=(char)tolower((unsigned char)t[i]),c->dvbapi_boxtype[i+1]='\0';
            return CFG_CB_OK;
        }
        if(!strcasecmp(k->key,"delay")){if(!cfg_parse_i32_range(k->value,0,60000,&v))goto bad;c->dvbapi_delay_ms=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"max_services")){if(!cfg_parse_i32_range(k->value,1,32,&v))goto bad;c->dvbapi_max_services=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"pmt_mode")){if(!cfg_parse_i32_range(k->value,0,6,&v)||(v!=0&&v!=6))goto bad;c->dvbapi_pmt_mode=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"listen_port")){if(!cfg_parse_i32_range(k->value,0,65535,&v))goto bad;c->dvbapi_listen_port=v;return CFG_CB_OK;}
        if(!strcasecmp(k->key,"serverip")){if(k->value[0]&&!cfg_parse_bindaddr(k->value))goto bad;tcmg_strlcpy(c->dvbapi_serverip,k->value[0]?k->value:"127.0.0.1",sizeof(c->dvbapi_serverip));return CFG_CB_OK;}
        goto unknown;
    }
    snprintf(err,esz,"line %d unknown section [%s]",k->line,sec);
    return CFG_CB_SKIP_SECTION;
unknown:
    snprintf(err,esz,"line %d section [%s] contains unknown setting '%s=%s'",k->line,sec,k->key,k->value);
    return CFG_CB_INVALID;
bad:
    snprintf(err,esz,"line %d section [%s] invalid value for '%s'",k->line,sec,k->key);
    return CFG_CB_INVALID;
}
bool cfg_parse_bindaddr(const char*s)
{
    struct in_addr a;
    return s&&inet_pton(AF_INET,s,&a)==1;
}
