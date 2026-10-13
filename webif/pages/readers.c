#define MODULE_LOG_PREFIX "webif"
#include "../service/service.h"
#include "../../src/core/utils.h"
#include "../../src/reader/protocol.h"
#include "../internal/proto.h"
#include <stdlib.h>
#include <string.h>
void send_page_readers(int fd)
{
    PAGE_INIT(24576)
    pos = emit_header(&buf, &bsz, pos, "Readers", "readers");
    S_WEBIF_READER_LIST_VIEW readers[MAX_READERS];
    int n = webif_reader_list_snapshot_all(readers, MAX_READERS);
    int enabled_n = 0;
    for (int i = 0; i < n; i++) if (readers[i].enabled) enabled_n++;
    pos=buf_printf(&buf,&bsz,pos,
        "<section class='utoolbar rtoolbar' aria-label='Readers toolbar'><div class='tgrp' id='rStats'>"
        "<button type='button' class='tool ust act' data-f='all' aria-pressed='true'>All <span class='n' id='rcnt_all'>%d</span></button>"
        "<button type='button' class='tool ust' data-f='enabled' aria-pressed='false'>Enabled <span class='n' id='rcnt_enabled'>%d</span></button>"
        "<button type='button' class='tool ust' data-f='disabled' aria-pressed='false'>Disabled <span class='n' id='rcnt_disabled'>%d</span></button>"
        "<button type='button' class='tool ust' data-f='card' aria-pressed='false'>Card <span class='n' id='rcnt_card'>0</span></button>"
        "<button type='button' class='tool ust' data-f='network' aria-pressed='false'>Network <span class='n' id='rcnt_network'>0</span></button>"
        "<button type='button' class='tool ust' data-f='emu' aria-pressed='false'>EMU <span class='n' id='rcnt_emu'>0</span></button></div>"
        "<div class='usrch'>" ICON("i-search") "<input id='rSearch' name='reader_filter' type='search' readonly placeholder='Search readers&hellip;' title='Search label, protocol, device, group or CAID' autocomplete='off' autocorrect='off' autocapitalize='off' spellcheck='false' inputmode='search' aria-label='Search readers'></div>"
        "<div class='tgrp'><button type='button' class='tool' data-a='refresh'>" ICON("i-refresh") "Refresh</button><button type='button' class='tool pri' data-a='add'>" ICON("i-plus") "Add Reader</button></div></section>", n,enabled_n,n-enabled_n);
    pos=buf_printf(&buf,&bsz,pos,
        "<section class='tw cm' id='rTable'><table class='rt'><thead><tr>"
        "<th data-k='enabled' class='c-rstate'><button type='button' class='table-sort' title='Enabled state' aria-label='Enabled state'>On<span class='sort-arrow' aria-hidden='true'></span></button></th>"
        "<th data-k='label'><button type='button' class='table-sort'>Name<span class='sort-arrow' aria-hidden='true'></span></button></th>"
        "<th data-k='protocol'><button type='button' class='table-sort'>Protocol<span class='sort-arrow' aria-hidden='true'></span></button></th>"
        "<th data-k='device'><button type='button' class='table-sort'>Address<span class='sort-arrow' aria-hidden='true'></span></button></th>"
        "<th data-k='groups'><button type='button' class='table-sort'>Group<span class='sort-arrow' aria-hidden='true'></span></button></th>"
        "<th data-k='caid'><button type='button' class='table-sort'>CAID<span class='sort-arrow' aria-hidden='true'></span></button></th><th data-k='cw_ok'><button type='button' class='table-sort' title='Successful CWs' aria-label='CW OK'>OK<span class='sort-arrow' aria-hidden='true'></span></button></th><th data-k='cw_nok'><button type='button' class='table-sort' title='Failed CWs' aria-label='CW NOK'>NOK<span class='sort-arrow' aria-hidden='true'></span></button></th><th class='c-btn'>Actions</th>"
        "</tr></thead><tbody id='rBody'>");
    for (int ri = 0; ri < n; ri++) {
        const S_WEBIF_READER_LIST_VIEW *r = &readers[ri];
        const char *rstate = !r->enabled ? "r-disabled" : r->active ? "r-active" : "r-idle";
        char l[256], p[64], d[512], g[256], c[256];
        html_escape(r->label, l, sizeof(l));
        html_escape(r->protocol, p, sizeof(p));
        html_escape(r->device, d, sizeof(d));
        html_escape(r->groups, g, sizeof(g));
        html_escape(r->caids, c, sizeof(c));
        const S_READER_PROTOCOL *rp=reader_protocol_find(r->protocol); const char *kind=rp&&rp->kind==READER_PROTOCOL_CARD?"card":rp&&rp->kind==READER_PROTOCOL_EMU?"emu":"network";
        pos=buf_printf(&buf,&bsz,pos,
            "<tr class='rrow' data-i='%d' data-enabled='%d' data-active='%d' data-kind='%s'><td class='c-rstate'><button type='button' class='pw-btn %s' data-a='toggle' title='%s reader' aria-label='%s reader'>" ICON("i-toggle") "</button></td>"
            "<td class='c-rlabel'><button type='button' class='rlink %s' data-a='edit' title='Edit %s'>%s</button></td><td class='c-rproto'><span class='badge %s'>%s</span></td>"
            "<td class='c-rdev mono'>%s</td><td class='c-rgroup mono'>%s</td><td class='c-rcaid mono'>%s</td><td class='c-rstat-ok mono'>%lld</td><td class='c-rstat-nok mono'>%lld</td><td class='c-btn'><div class='ba'>"
            "<button type='button' class='act-b ed' data-a='edit' title='Edit reader' aria-label='Edit reader'>" ICON("i-edit") "</button>"
            "<button type='button' class='act-b dl' data-a='delete' title='Delete reader' aria-label='Delete reader'>" ICON("i-trash") "</button></div></td></tr>",
            r->index,r->enabled,r->active,kind,
            r->enabled?"on":"off",r->enabled?"Disable":"Enable",r->enabled?"Disable":"Enable",rstate,l,l,
            rp&&rp->kind==READER_PROTOCOL_CARD?"bcy":rp&&rp->kind==READER_PROTOCOL_EMU?"bvi":"bbl",p,d[0]?d:"&mdash;",g[0]?g:"&mdash;",c[0]?c:"&mdash;",
            (long long)r->cw_ok,(long long)r->cw_nok);
    }
    if(n==0) pos=buf_printf(&buf,&bsz,pos,"<tr class='erow'><td colspan='9'>No readers</td></tr>");
    pos=buf_printf(&buf,&bsz,pos,"</tbody></table><div class='uempty' id='rEmpty' hidden>" ICON("i-key") "<b id='reT'>No readers</b><span id='reS'></span><button type='button' class='tool pri' id='reB' data-a='add'>" ICON("i-plus") "Add Reader</button></div></section>");
    pos=buf_printf(&buf,&bsz,pos,
        "<div class='mo' id='rModal' hidden><div class='mc reader-modal' role='dialog' aria-modal='true' aria-labelledby='rTitle'><div class='mh'><h2 id='rTitle'>Reader</h2><button type='button' class='ib' onclick='closeReader()' aria-label='Close'>" ICON("i-x") "</button></div><div class='mb'><input type='hidden' id='rIndex' value='-1'>"
        "<div class='reader-topgrid'><div class='fg'><label class='fld' for='rLabel'>Label</label><input class='fi' id='rLabel' autocomplete='off'></div><div class='fg'><label class='fld' for='rProtocol'>Protocol</label><select class='fi' id='rProtocol'>"
        "<option value='cccam'>CCcam</option><option value='newcamd'>Newcamd</option><option value='mgcamd'>MGcamd</option><option value='cs378x'>CS378X</option><option value='emu'>EMU</option><option value='pcsc'>PCSC</option><option value='internal'>Internal</option><option value='serial'>Serial / Phoenix</option></select></div></div>"
        "<div id='rCccamFields'><div class='reader-cccam-grid'><div class='fg'><label class='fld' for='rCccamDevice'>Server</label><input class='fi mono' id='rCccamDevice' placeholder='host,port' autocomplete='off'></div><div class='fg'><label class='fld' for='rUser'>Username</label><input class='fi' id='rUser' autocomplete='off'></div><div class='fg'><label class='fld' for='rPassword'>Password</label><input class='fi' id='rPassword' type='password' autocomplete='off'></div><div class='fg'><label class='fld' for='rTimeout'>Timeout (s)</label><input class='fi mono' id='rTimeout' type='number' min='1' max='600'></div><div class='fg' id='rKeyWrap' hidden><label class='fld' for='rKey'>DES Key</label><input class='fi mono' id='rKey' maxlength='28' spellcheck='false' placeholder='28 hex chars' autocomplete='off'></div></div></div>"
        "<div id='rPcscFields' hidden><div class='reader-pcsc-grid'><div class='fg'><label class='fld' for='rPcscDevice'>PCSC reader</label><input class='fi mono' id='rPcscDevice' placeholder='reader name or index' autocomplete='off'></div><div class='fg'><label class='fld' for='rPoll'>Poll (ms)</label><input class='fi mono' id='rPoll' type='number' min='50' max='10000'></div></div></div>");
    pos=buf_printf(&buf,&bsz,pos,
        "<div id='rInternalFields' hidden><div class='reader-pcsc-grid'><div class='fg'><label class='fld' for='rInternalDevice'>Internal reader</label><input class='fi mono' id='rInternalDevice' placeholder='auto (recommended) or /dev/sci0' autocomplete='off'></div></div></div>"
        "<div id='rSerialFields' hidden><div class='reader-pcsc-grid'><div class='fg'><label class='fld' for='rSerialDevice'>Serial port</label><input class='fi mono' id='rSerialDevice' list='rSerialPorts' placeholder='COM3 or /dev/ttyUSB0' autocomplete='off'></div><div class='fg'><label class='fld' for='rSerialPoll'>Poll (ms)</label><input class='fi mono' id='rSerialPoll' type='number' min='50' max='10000'></div></div><datalist id='rSerialPorts'></datalist></div>"
        "<div id='rCardMaintenanceFields' hidden><div class='reader-pcsc-grid'><div class='fg'><label class='fld' for='rMaintMode'>Maintenance</label><select class='fi' id='rMaintMode'><option value='fast_reset'>Fast Reset</option><option value='old_ecm'>Old ECM</option></select></div><div class='fg' id='rFastWrap'><label class='fld' for='rFast'>Fast reset interval (s)</label><input class='fi mono' id='rFast' type='number' min='0' max='86400'></div><div class='fg' id='rFastIdleWrap'><label class='fld' for='rFastIdle'>Pause reset after idle (s)</label><input class='fi mono' id='rFastIdle' type='number' min='0' max='86400'></div><div class='fg' id='rOldSourceWrap'><label class='fld' for='rOldSource'>Old ECM source</label><select class='fi' id='rOldSource'><option value='auto'>Auto — first successful ECM</option><option value='manual'>Manual ECM</option></select></div><div class='fg' id='rOldSuccessesWrap' hidden><label class='fld' for='rOldSuccesses'>Successful ECM count</label><input class='fi mono' id='rOldSuccesses' type='number' min='1' max='1000000'></div><div class='fg' id='rOldEcmWrap' hidden><label class='fld' for='rOldEcm'>Manual ECM (hex)</label><textarea class='ea mono' id='rOldEcm' maxlength='498' rows='3' spellcheck='false' placeholder='81703470...'></textarea></div></div></div>"
        "<div id='rEmuFields' hidden><div class='fg'><label class='fld' for='rKeys'>ECM keys</label><textarea class='ea mono' id='rKeys' spellcheck='false' placeholder='0B00=64 hex characters'></textarea></div></div>");
    pos=buf_printf(&buf,&bsz,pos,
        "<div class='reader-routing-grid'><div class='fg'><label class='fld' for='rCaid'>CAID</label><input class='fi mono' id='rCaid' placeholder='0B02,0B07' autocomplete='off' spellcheck='false'></div><div class='fg'><label class='fld' for='rIdent'>IDENT</label><input class='fi mono' id='rIdent' placeholder='0B00:000001' autocomplete='off' spellcheck='false'></div><div class='fg'><label class='fld' for='rSid'>SID whitelist</label><input class='fi mono' id='rSid' placeholder='0064,00C8,1234' autocomplete='off'></div><div class='fg'><label class='fld' for='rWl'>ECM whitelist</label><input class='fi mono' id='rWl' maxlength='2' placeholder='37' autocomplete='off'></div><div class='fg'><label class='fld' for='rGroup'>Group</label><input class='fi mono' id='rGroup' placeholder='1,5' autocomplete='off'></div><label class='reader-enable'><span>Enabled</span><input id='rEnabled' type='checkbox' checked></label></div><div id='rErr' class='le' hidden><span id='rErrMsg'></span></div><div class='mf'><button type='button' class='btn bg' onclick='closeReader()'>Cancel</button><button type='button' class='btn bp' id='rSave' onclick='saveReader()'>Save</button></div></div></div>");
    pos=buf_printf(&buf,&bsz,pos,"<script src='/assets/readers.js?v=" TCMG_ASSET_REV "' defer></script>");
    pos=emit_footer(&buf,&bsz,pos); PAGE_SEND_AND_FREE(fd);
}
