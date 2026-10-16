#define MODULE_LOG_PREFIX "conf"
#include "config_internal.h"
void cfg_str_trim(char *s)
{
    char *p,*q;
    if(!s)return;
    p=s;
    while(*p&&isspace((unsigned char)*p))p++;
    if(p!=s)memmove(s,p,strlen(p)+1);
    if(!*s)return;
    q=s+strlen(s)-1;
    while(q>=s&&isspace((unsigned char)*q))*q--='\0';
}
bool cfg_parse_file(const char *path,cfg_kv_callback cb,void *ctx,char *err,size_t errsz)
{
    FILE*f;
    char line[4096],section[128]="";
    int line_no=0,section_valid=0;
    if(!path||!cb||!err||!errsz)return false;
    f=fopen(path,"r");
    if(!f){
        if(errno==ENOENT)return true;
        snprintf(err,errsz,"%s: %s",path,strerror(errno));
        return false;
    }
    while(fgets(line,sizeof(line),f)){
        char*eq;
        S_KV kv;
        E_CFG_CB_RESULT rc;
        line_no++;
        if(!strchr(line,'\n')&&!feof(f)){
            int ch;
            while((ch=fgetc(f))!=EOF && ch!='\n') { }
            fprintf(stderr,"WARNING: %s line %d line too long ignored\n",path,line_no);
            section_valid=0;
            continue;
        }
        cfg_str_trim(line);
        if(!line[0]||line[0]=='#')continue;
        if(line[0]=='['){
            char*r=strrchr(line,']');
            size_t n;
            section_valid=0;
            if(!r||r==line+1||r[1]){
                fprintf(stderr,"WARNING: %s line %d invalid section ignored\n",path,line_no);
                continue;
            }
            *r='\0';
            n=strlen(line+1);
            if(n>=sizeof(section)){
                fprintf(stderr,"WARNING: %s line %d section name too long ignored\n",path,line_no);
                continue;
            }
            tcmg_strlcpy(section,line+1,sizeof(section));
            section_valid=1;
            continue;
        }
        if(!section_valid){
            fprintf(stderr,"WARNING: %s line %d setting outside a valid section ignored\n",path,line_no);
            continue;
        }
        eq=strchr(line,'=');
        if(!eq){
            fprintf(stderr,"WARNING: %s line %d invalid line ignored\n",path,line_no);
            continue;
        }
        *eq='\0';
        memset(&kv,0,sizeof(kv));
        cfg_str_trim(line);
        if(!line[0]||strlen(line)>=sizeof(kv.key)){
            fprintf(stderr,"WARNING: %s line %d invalid key ignored\n",path,line_no);
            continue;
        }
        tcmg_strlcpy(kv.key,line,sizeof(kv.key));
        cfg_strip_inline_comment(eq+1);
        if(strlen(eq+1)>=sizeof(kv.value)){
            fprintf(stderr,"WARNING: %s line %d value too long for '%s' ignored\n",path,line_no,kv.key);
            continue;
        }
        tcmg_strlcpy(kv.value,eq+1,sizeof(kv.value));
        kv.line=line_no;
        err[0]='\0';
        rc=cb(section,&kv,ctx,err,errsz);
        if(rc==CFG_CB_OK)continue;
        if(!err[0])snprintf(err,errsz,"%s:%d: invalid setting",path,line_no);
        fprintf(stderr,"WARNING: %s: %s\n",path,err);
        if(rc==CFG_CB_SKIP_SECTION)section_valid=0;
    }
    if(ferror(f)){
        snprintf(err,errsz,"%s: read error",path);
        fclose(f);
        return false;
    }
    fclose(f);
    return true;
}
bool cfg_parse_bool(const char*s,bool*out)
{
    if(!s||!out)return false;
    if(!strcasecmp(s,"1")||!strcasecmp(s,"yes")||!strcasecmp(s,"true")||!strcasecmp(s,"on")){*out=true;return true;}
    if(!strcasecmp(s,"0")||!strcasecmp(s,"no")||!strcasecmp(s,"false")||!strcasecmp(s,"off")){*out=false;return true;}
    return false;
}
bool cfg_parse_i32_range(const char*s,int32_t lo,int32_t hi,int32_t*out)
{
    char*e=NULL;
    int64_t v;
    if(!s||!*s||!out)return false;
    errno=0;
    v=strtoll(s,&e,10);
    if(errno||e==s||*e||v<(int64_t)lo||v>(int64_t)hi)return false;
    *out=(int32_t)v;
    return true;
}
bool cfg_parse_hex_bytes(const char*s,uint8_t*out,size_t n)
{
    if(!s||!out||strlen(s)!=n*2)return false;
    for(size_t i=0;i<n*2;i++)if(!isxdigit((unsigned char)s[i]))return false;
    for(size_t i=0;i<n;i++){
        unsigned v;
        if(sscanf(s+i*2,"%02X",&v)!=1)return false;
        out[i]=(uint8_t)v;
    }
    return true;
}
bool cfg_parse_u8_hex(const char*s,uint8_t*out)
{
    char*e=NULL;
    unsigned long v;
    if(!s||!*s||!out)return false;
    errno=0;
    v=strtoul(s,&e,16);
    if(errno||e==s||*e||v>0xFFUL)return false;
    *out=(uint8_t)v;
    return true;
}
bool cfg_parse_u16_hex(const char*s,uint16_t*out)
{
    char*e=NULL;
    unsigned long v;
    if(!s||!*s||!out)return false;
    errno=0;
    v=strtoul(s,&e,16);
    if(errno||e==s||*e||v>0xFFFFUL)return false;
    *out=(uint16_t)v;
    return true;
}
bool cfg_parse_ident_list(const char*s,S_IDENT_FILTER*out,int32_t*count,int32_t maxn)
{
    char buf[CFGVAL_LEN],*save=NULL,*tok;
    int32_t n=0;
    if(!out||!count||maxn<=0||maxn>MAX_IDENT_FILTERS)return false;
    tcmg_strlcpy(buf,s?s:"",sizeof(buf));
    if(!buf[0]){*count=0;return true;}
    tok=strtok_r(buf,",;",&save);
    while(tok){
        char *colon,*end;
        unsigned long caid,provid;
        cfg_str_trim(tok);
        if(!*tok||n>=maxn)return false;
        colon=strchr(tok,':');
        if(!colon||colon==tok||strchr(colon+1,':'))return false;
        *colon='\0';
        cfg_str_trim(tok);
        cfg_str_trim(colon+1);
        if(strlen(tok)>4||strlen(colon+1)>8||!*tok||!* (colon+1))return false;
        errno=0;
        caid=strtoul(tok,&end,16);
        if(errno||end==tok||*end||caid>0xFFFFUL||caid==0)return false;
        errno=0;
        provid=strtoul(colon+1,&end,16);
        if(errno||end==colon+1||*end||provid>0xFFFFFFFFUL)return false;
        for(int32_t i=0;i<n;i++)
            if(out[i].caid==(uint16_t)caid&&out[i].provid==(uint32_t)provid)return false;
        out[n].caid=(uint16_t)caid;
        out[n].provid=(uint32_t)provid;
        n++;
        tok=strtok_r(NULL,",;",&save);
    }
    *count=n;
    return true;
}
bool cfg_parse_group_list(const char*s,int32_t*groups,int32_t*count)
{
    char buf[CFGVAL_LEN],*save=NULL,*tok;
    int32_t n=0;
    tcmg_strlcpy(buf,s?s:"",sizeof(buf));
    if(!buf[0])return false;
    tok=strtok_r(buf,",",&save);
    while(tok){
        int32_t v;
        cfg_str_trim(tok);
        if(!*tok||n>=MAX_GROUPS_PER_ACC||!cfg_parse_i32_range(tok,1,65535,&v))return false;
        for(int i=0;i<n;i++)if(groups[i]==(int32_t)v)return false;
        groups[n++]=v;
        tok=strtok_r(NULL,",",&save);
    }
    *count=n;
    return n>0;
}
bool cfg_parse_u16_list(const char*s,uint16_t*out,int32_t*count,int32_t maxn)
{
    char buf[CFGVAL_LEN],*save=NULL,*tok;
    int32_t n=0;
    if(!s||!out||!count||maxn<=0)return false;
    *count=0;
    if(!*s)return true;
    tcmg_strlcpy(buf,s,sizeof(buf));
    tok=strtok_r(buf,",",&save);
    while(tok){
        uint16_t v;
        cfg_str_trim(tok);
        if(!*tok||n>=maxn||!cfg_parse_u16_hex(tok,&v))return false;
        for(int i=0;i<n;i++)if(out[i]==v)return false;
        out[n++]=v;
        tok=strtok_r(NULL,",",&save);
    }
    *count=n;
    return true;
}
bool cfg_parse_ipv4_list(const char*s,char out[][MAXIPLEN],int32_t*count)
{
    char buf[CFGVAL_LEN],*save=NULL,*tok;
    int32_t n=0;
    if(!s||!out||!count)return false;
    *count=0;
    if(!*s)return true;
    tcmg_strlcpy(buf,s,sizeof(buf));
    tok=strtok_r(buf,",",&save);
    while(tok){
        struct in_addr a;
        cfg_str_trim(tok);
        if(!*tok||n>=MAX_IP_WHITELIST||inet_pton(AF_INET,tok,&a)!=1)return false;
        tcmg_strlcpy(out[n++],tok,MAXIPLEN);
        tok=strtok_r(NULL,",",&save);
    }
    *count=n;
    return true;
}
bool cfg_parse_ecm_key(const char*s,uint16_t def_caid,S_ECMKEY*out)
{
    const char*eq;
    const char*hex;
    char caid_text[5];
    if(!s||!out)return false;
    memset(out,0,sizeof(*out));
    out->caid=def_caid;
    eq=strchr(s,'=');
    hex=s;
    if(eq){
        if((size_t)(eq-s)!=4)return false;
        memcpy(caid_text,s,4);
        caid_text[4]='\0';
        if(!cfg_parse_u16_hex(caid_text,&out->caid))return false;
        hex=eq+1;
    }
    if(strlen(hex)!=64)return false;
    for(int i=0;i<64;i++)if(!isxdigit((unsigned char)hex[i]))return false;
    for(int i=0;i<16;i++){
        unsigned v0=0,v1=0;
        if(sscanf(hex+i*2,"%2X",&v0)!=1)return false;
        if(sscanf(hex+32+i*2,"%2X",&v1)!=1)return false;
        out->key0[i]=(uint8_t)v0;
        out->key1[i]=(uint8_t)v1;
    }
    return true;
}
bool cfg_parse_date(const char*s,time_t*out)
{
    int y,m,d;
    char extra;
    struct tm t,check;
    time_t value;
    if(!s||!out)return false;
    if(!strcmp(s,"0")||!*s){*out=false;return true;}
    if(sscanf(s,"%d-%d-%d%c",&y,&m,&d,&extra)!=3)return false;
    if(y<1970||y>2200||m<1||m>12||d<1||d>31)return false;
    memset(&t,0,sizeof(t));
    t.tm_year=y-1900;
    t.tm_mon=m-1;
    t.tm_mday=d;
    t.tm_isdst=-1;
    value=mktime(&t);
    if(value<0)return false;
    if(!localtime_r(&value,&check))return false;
    if(check.tm_year!=y-1900||check.tm_mon!=m-1||check.tm_mday!=d)return false;
    *out=value;
    return true;
}
bool cfg_parse_schedule(const char*s,S_ACCOUNT*a)
{
    static const char*days[]={"MON","TUE","WED","THU","FRI","SAT","SUN"};
    char buf[64],d1[4]="",d2[4]="",*sp,*dash;
    int from=-1,to=-1,h1,m1,h2,m2;
    char extra;
    if(!s||!*s){a->sched_day_from=-1;a->schedule[0]='\0';return true;}
    tcmg_strlcpy(buf,s,sizeof(buf));
    sp=strchr(buf,' ');
    if(!sp)return false;
    *sp='\0';
    dash=strchr(buf,'-');
    if(dash){
        size_t n=(size_t)(dash-buf);
        if(n>3||strlen(dash+1)>3)return false;
        memcpy(d1,buf,n);
        d1[n]='\0';
        tcmg_strlcpy(d2,dash+1,sizeof(d2));
    }else{
        tcmg_strlcpy(d1,buf,sizeof(d1));
        tcmg_strlcpy(d2,buf,sizeof(d2));
    }
    for(int i=0;i<7;i++){
        if(!strcasecmp(d1,days[i]))from=i;
        if(!strcasecmp(d2,days[i]))to=i;
    }
    if(from<0||to<0||sscanf(sp+1,"%d:%d-%d:%d%c",&h1,&m1,&h2,&m2,&extra)!=4)return false;
    if(h1<0||h1>23||m1<0||m1>59||h2<0||h2>23||m2<0||m2>59)return false;
    a->sched_day_from=(int8_t)from;
    a->sched_day_to=(int8_t)to;
    a->sched_hhmm_from=(int16_t)(h1*100+m1);
    a->sched_hhmm_to=(int16_t)(h2*100+m2);
    tcmg_strlcpy(a->schedule,s,sizeof(a->schedule));
    return true;
}
void cfg_strip_inline_comment(char*s)
{
    bool quoted=false;
    if(!s)return;
    for(char*p=s;*p;p++){
        if(*p=='"')quoted=!quoted;
        if(*p=='#'&&!quoted&&p>s&&isspace((unsigned char)p[-1])){*p='\0';break;}
    }
    cfg_str_trim(s);
}
