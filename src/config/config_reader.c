#define MODULE_LOG_PREFIX "conf"
#include "config_internal.h"
#include "../reader/protocol.h"
#include "../reader/rules.h"
S_READER*cfg_reader_new(S_CONFIG*cfg,int index)
{
    S_READER*r;
    if(!cfg||index<0||index>=MAX_READERS)return NULL;
    r=&cfg->readers[index];
    if(!r->in_use){
        memset(r,0,sizeof(*r));
        r->in_use=1;
        r->enabled=1;
        r->inactivitytimeout=30;
        r->ecm_whitelist=0;
        r->fast_reset_idle=300;
        r->maintenance_mode=TCMG_READER_MAINT_FAST_RESET;
        r->old_ecm_source=TCMG_OLD_ECM_SOURCE_AUTO;
        r->old_ecm_successes=10;
        r->ngroups=1;
        r->groups[0]=1;
        tcmg_strlcpy(r->protocol,"emu",sizeof(r->protocol));
        cfg->nreaders++;
    }
    return r;
}
bool cfg_parse_readers(const char*path,S_CONFIG*c,char*err,size_t esz)
{
    FILE*f=fopen(path,"r");
    char line[4096],sec[64]="",key[128];
    bool used[MAX_READERS]={false};
    int line_no=0,section_active=0;
    S_READER*reader=NULL;
    if(!f){
        if(errno==ENOENT)return true;
        snprintf(err,esz,"%s: %s",path,strerror(errno));
        return false;
    }
    while(fgets(line,sizeof(line),f)){
        line_no++;
        if(!strchr(line,'\n')&&!feof(f)){
            fprintf(stderr,"WARNING: %s line %d line too long ignored\n",path,line_no);
            section_active=0;
            reader=NULL;
            continue;
        }
        cfg_str_trim(line);
        if(!line[0]||line[0]=='#')continue;
        if(line[0]=='['){
            char*rr=strrchr(line,']');
            int index=-1;
            section_active=0;
            reader=NULL;
            if(!rr||rr==line+1||rr[1]){fprintf(stderr,"WARNING: %s line %d invalid section ignored\n",path,line_no);continue;}
            *rr='\0';
            if(strlen(line+1)>=sizeof(sec)){fprintf(stderr,"WARNING: %s line %d section name too long ignored\n",path,line_no);continue;}
            tcmg_strlcpy(sec,line+1,sizeof(sec));
            if(strcasecmp(sec,"reader")){fprintf(stderr,"WARNING: %s line %d unknown section [%s] ignored\n",path,line_no,sec);continue;}
            for(int i=0;i<MAX_READERS;i++){
                if(!used[i]){index=i;break;}
            }
            if(index<0){fprintf(stderr,"WARNING: %s line %d maximum number of readers (%d) reached; section ignored\n",path,line_no,MAX_READERS);continue;}
            used[index]=true;
            reader=cfg_reader_new(c,index);
            if(!reader){snprintf(err,esz,"%s:%d: cannot allocate reader",path,line_no);fclose(f);return false;}
            section_active=1;
            continue;
        }
        if(!section_active||!reader){fprintf(stderr,"WARNING: %s line %d setting outside a valid [reader] section ignored\n",path,line_no);continue;}
        char*eq=strchr(line,'=');
        char value[CFGVAL_LEN];
        int32_t v;
        bool b;
        if(!eq){fprintf(stderr,"WARNING: %s line %d invalid line in [reader] ignored\n",path,line_no);continue;}
        *eq='\0';
        cfg_str_trim(line);
        if(!line[0]||strlen(line)>=sizeof(key)){fprintf(stderr,"WARNING: %s line %d invalid key in [reader] ignored\n",path,line_no);continue;}
        cfg_strip_inline_comment(eq+1);
        if(strlen(eq+1)>=sizeof(value)){fprintf(stderr,"WARNING: %s line %d value too long for '%s' ignored\n",path,line_no,line);continue;}
        tcmg_strlcpy(key,line,sizeof(key));
        tcmg_strlcpy(value,eq+1,sizeof(value));
        if(!strcasecmp(key,"label")){if(strlen(value)>=sizeof(reader->label)){fprintf(stderr,"WARNING: %s line %d invalid value for 'label' ignored\n",path,line_no);continue;}tcmg_strlcpy(reader->label,value,sizeof(reader->label));}
        else if(!strcasecmp(key,"protocol")){if(!reader_protocol_find(value)){fprintf(stderr,"WARNING: %s line %d invalid value for 'protocol' ignored\n",path,line_no);continue;}tcmg_strlcpy(reader->protocol,value,sizeof(reader->protocol));}
        else if(!strcasecmp(key,"enabled")){if(!cfg_parse_bool(value,&b)){fprintf(stderr,"WARNING: %s line %d invalid value for 'enabled' ignored\n",path,line_no);continue;}reader->enabled=b;}
        else if(!strcasecmp(key,"device")){if(strlen(value)>=sizeof(reader->device)){fprintf(stderr,"WARNING: %s line %d invalid value for 'device' ignored\n",path,line_no);continue;}tcmg_strlcpy(reader->device,value,sizeof(reader->device));}
        else if(!strcasecmp(key,"user")){if(strlen(value)>=sizeof(reader->user)){fprintf(stderr,"WARNING: %s line %d invalid value for 'user' ignored\n",path,line_no);continue;}tcmg_strlcpy(reader->user,value,sizeof(reader->user));}
        else if(!strcasecmp(key,"password")){if(strlen(value)>=sizeof(reader->password)){fprintf(stderr,"WARNING: %s line %d invalid value for 'password' ignored\n",path,line_no);continue;}tcmg_strlcpy(reader->password,value,sizeof(reader->password));}
        else if(!strcasecmp(key,"group")){if(!cfg_parse_group_list(value,reader->groups,&reader->ngroups)){fprintf(stderr,"WARNING: %s line %d invalid value for 'group' ignored\n",path,line_no);continue;}}
        else if(!strcasecmp(key,"caid")){if(!cfg_parse_u16_list(value,reader->caids,&reader->ncaids,MAX_CAIDS_PER_READER)){fprintf(stderr,"WARNING: %s line %d invalid value for 'caid' ignored\n",path,line_no);continue;}}
        else if(!strcasecmp(key,"ident")){if(!cfg_parse_ident_list(value,reader->idents,&reader->nidents,MAX_IDENT_FILTERS)){fprintf(stderr,"WARNING: %s line %d invalid value for 'ident' ignored\n",path,line_no);continue;}}
        else if(!strcasecmp(key,"sid_whitelist")){if(!cfg_parse_u16_list(value,reader->sid_whitelist,&reader->nsid_whitelist,MAX_SID_WHITELIST)){fprintf(stderr,"WARNING: %s line %d invalid value for 'sid_whitelist' ignored\n",path,line_no);continue;}}
        else if(!strcasecmp(key,"ecmwhitelist")){if(!reader_ecm_whitelist_parse(reader,value)){fprintf(stderr,"WARNING: %s line %d invalid value for 'ecmwhitelist' ignored\n",path,line_no);continue;}}
        else if(!strcasecmp(key,"inactivitytimeout")){if(!cfg_parse_i32_range(value,1,600,&v)){fprintf(stderr,"WARNING: %s line %d invalid value for 'inactivitytimeout' ignored\n",path,line_no);continue;}reader->inactivitytimeout=v;}
        else if(!strcasecmp(key,"do_ecm")){if(!cfg_parse_bool(value,&b)){fprintf(stderr,"WARNING: %s line %d invalid value for 'do_ecm' ignored\n",path,line_no);continue;}}
        else if(!strcasecmp(key,"deprecated")){if(!cfg_parse_i32_range(value,0,1,&v)){fprintf(stderr,"WARNING: %s line %d invalid value for 'deprecated' ignored\n",path,line_no);continue;}reader->deprecated=v;}
        else if(!strcasecmp(key,"fast_reset")){if(!cfg_parse_i32_range(value,0,86400,&v)){fprintf(stderr,"WARNING: %s line %d invalid value for 'fast_reset' ignored\n",path,line_no);continue;}reader->fast_reset=v;}
        else if(!strcasecmp(key,"fast_reset_idle")){if(!cfg_parse_i32_range(value,0,86400,&v)){fprintf(stderr,"WARNING: %s line %d invalid value for 'fast_reset_idle' ignored\n",path,line_no);continue;}reader->fast_reset_idle=v;}
        else if(!strcasecmp(key,"maintenance_mode")){if(!strcasecmp(value,"fast_reset")) reader->maintenance_mode=TCMG_READER_MAINT_FAST_RESET; else if(!strcasecmp(value,"old_ecm")) reader->maintenance_mode=TCMG_READER_MAINT_OLD_ECM; else {fprintf(stderr,"WARNING: %s line %d invalid value for 'maintenance_mode' ignored\n",path,line_no);continue;}}
        else if(!strcasecmp(key,"old_ecm_source")){if(!strcasecmp(value,"auto")) reader->old_ecm_source=TCMG_OLD_ECM_SOURCE_AUTO; else if(!strcasecmp(value,"manual")) reader->old_ecm_source=TCMG_OLD_ECM_SOURCE_MANUAL; else {fprintf(stderr,"WARNING: %s line %d invalid value for 'old_ecm_source' ignored\n",path,line_no);continue;}}
        else if(!strcasecmp(key,"old_ecm_trigger")||!strcasecmp(key,"old_ecm_interval")){ }
        else if(!strcasecmp(key,"old_ecm_successes")){if(!cfg_parse_i32_range(value,1,1000000,&v)){fprintf(stderr,"WARNING: %s line %d invalid value for 'old_ecm_successes' ignored\n",path,line_no);continue;}reader->old_ecm_successes=v;}
        else if(!strcasecmp(key,"old_ecm")){size_t len=strlen(value);bool valid=len<=TCMG_OLD_ECM_HEX_LEN&&!(len&1u);for(size_t i=0;valid&&i<len;i++)if(!isxdigit((unsigned char)value[i]))valid=false;if(!valid){fprintf(stderr,"WARNING: %s line %d invalid value for 'old_ecm' ignored\n",path,line_no);continue;}tcmg_strlcpy(reader->old_ecm,value,sizeof(reader->old_ecm));}
        else if(!strcasecmp(key,"poll_ms")){if(!cfg_parse_i32_range(value,25,10000,&v)){fprintf(stderr,"WARNING: %s line %d invalid value for 'poll_ms' ignored\n",path,line_no);continue;}reader->poll_ms=v;}
        else if(!strcasecmp(key,"key")){if(!cfg_parse_hex_bytes(value,reader->newcamd_key,14)){fprintf(stderr,"WARNING: %s line %d invalid value for 'key' ignored\n",path,line_no);continue;}}
        else if(!strcasecmp(key,"ecmkey")){
            uint16_t def_caid=reader->ncaids?reader->caids[0]:0;
            S_ECMKEY key_value;
            bool found=false;
            if(reader->nkeys>=MAX_ECMKEYS_PER_ACC||!cfg_parse_ecm_key(value,def_caid,&key_value)){fprintf(stderr,"WARNING: %s line %d invalid value for 'ecmkey' ignored\n",path,line_no);continue;}
            for(int i=0;i<reader->nkeys;i++){
                if(reader->keys[i].caid==key_value.caid){reader->keys[i]=key_value;found=true;break;}
            }
            if(!found)reader->keys[reader->nkeys++]=key_value;
        }
        else fprintf(stderr,"WARNING: %s line %d section [reader] contains unknown setting '%s=%s' ignored\n",path,line_no,key,value);
    }
    fclose(f);
    for(int i=0;i<MAX_READERS;i++){
        reader=&c->readers[i];
        if(!reader->in_use)continue;
        if(!reader->label[0])snprintf(reader->label,sizeof(reader->label),"reader%d",i+1);
    }
    return true;
}
