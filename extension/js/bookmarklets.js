// ══════════════════════════════════════════════════════════════════
// Bookmarklets — built-in audit helpers + custom user bookmarklets.
// Runs a bookmarklet's JavaScript on the active browser tab via the
// chrome.scripting API (MV3). Stored custom bookmarklets persist in
// chrome.storage.local.
// ══════════════════════════════════════════════════════════════════

const BUILTIN_BOOKMARKLETS = [
    {
        id: 'nuclear_reveal',
        name: '🛠 Smart Reveal Mode',
        desc: 'Reveals hidden/disabled/readonly/collapsed elements & outlines them in red. Run again to restore. (toggleable)',
        code: `(function(){const ID="smart-reveal-mode";const OLD=document.getElementById(ID);if(OLD){document.querySelectorAll("[data-sr-hidden]").forEach(e=>{e.hidden=e.dataset.srHidden==="1";delete e.dataset.srHidden;});document.querySelectorAll("[data-sr-disabled]").forEach(e=>{e.disabled=e.dataset.srDisabled==="1";delete e.dataset.srDisabled;});document.querySelectorAll("[data-sr-readonly]").forEach(e=>{e.readOnly=e.dataset.srReadonly==="1";delete e.dataset.srReadonly;});document.querySelectorAll("[data-sr-style]").forEach(e=>{e.setAttribute("style",e.dataset.srStyle);delete e.dataset.srStyle;});document.querySelectorAll("[data-sr-details]").forEach(e=>{e.open=e.dataset.srDetails==="1";delete e.dataset.srDetails;});document.querySelectorAll("[data-smart-revealed]").forEach(e=>e.removeAttribute("data-smart-revealed"));OLD.remove();alert("Smart Reveal deactivated");return;}const style=document.createElement("style");style.id=ID;style.textContent="[data-smart-revealed]{outline:2px dashed #ff3b30 !important;outline-offset:1px !important;}";document.head.appendChild(style);const skip=e=>!e||["SCRIPT","STYLE","META","LINK","HEAD","TITLE","BASE","NOSCRIPT","TEMPLATE"].includes(e.tagName);const saveStyle=e=>{if(!e.hasAttribute("data-sr-style"))e.dataset.srStyle=e.getAttribute("style")||"";};document.querySelectorAll("[hidden]").forEach(e=>{if(skip(e))return;e.dataset.srHidden=e.hidden?"1":"0";e.hidden=false;e.setAttribute("data-smart-revealed","");});document.querySelectorAll("*").forEach(e=>{if(skip(e))return;const cs=getComputedStyle(e);if(cs.display==="none"){saveStyle(e);e.style.setProperty("display","revert","important");if(getComputedStyle(e).display==="none")e.style.setProperty("display","block","important");e.setAttribute("data-smart-revealed","");}if(cs.visibility==="hidden"||cs.visibility==="collapse"){saveStyle(e);e.style.setProperty("visibility","visible","important");e.setAttribute("data-smart-revealed","");}if(parseFloat(cs.opacity)===0){saveStyle(e);e.style.setProperty("opacity","1","important");e.setAttribute("data-smart-revealed","");}});document.querySelectorAll("input[disabled],button[disabled],select[disabled],textarea[disabled]").forEach(e=>{e.dataset.srDisabled=e.disabled?"1":"0";e.disabled=false;e.setAttribute("data-smart-revealed","");});document.querySelectorAll("input[readonly],textarea[readonly]").forEach(e=>{e.dataset.srReadonly=e.readOnly?"1":"0";e.readOnly=false;e.setAttribute("data-smart-revealed","");});document.querySelectorAll("details:not([open])").forEach(e=>{e.dataset.srDetails=e.open?"1":"0";e.open=true;e.setAttribute("data-smart-revealed","");});const count=document.querySelectorAll("[data-smart-revealed]").length;alert("🛠️ Smart Reveal: "+count+" elements modified. Run again to restore them.");})();`,
    },
    {
        id: 'xray',
        name: '🚀 X-Ray',
        desc: 'Non-destructive: only removes hiding/disabling attributes & inline CSS rules.',
        code: `(function(){['hidden','disabled','readonly'].forEach(a=>document.querySelectorAll('['+a+']').forEach(e=>e.removeAttribute(a)));document.querySelectorAll('[style]').forEach(e=>{let s=e.style;if(s.display==='none')s.removeProperty('display');if(s.visibility==='hidden')s.removeProperty('visibility');if(s.opacity==='0')s.removeProperty('opacity');if(s.pointerEvents==='none'){s.removeProperty('pointer-events');s.removeProperty('opacity');}});document.querySelectorAll('details').forEach(d=>d.open=true);alert('✅ Hidden/disabled elements revealed!');})();`,
    },
    {
        id: 'enable_fields',
        name: '🔖 Enable Disabled/Readonly Fields',
        desc: 'Re-enable all disabled or readonly form fields on the page.',
        code: `(function(){document.querySelectorAll('[disabled],[readonly]').forEach(el=>{el.removeAttribute('disabled');el.removeAttribute('readonly');});})();`,
    },
    {
        id: 'unhide_display_none',
        name: '🔖 Unhide display:none Elements',
        desc: 'Reveals elements hidden with inline style display: none.',
        code: `(function(){document.querySelectorAll('[style*="display: none"]').forEach(el=>{el.style.display='block';});})();`,
    },
    {
        id: 'enable_pointer_events',
        name: '🔖 Re-enable pointer-events',
        desc: 'Restores interactions blocked with pointer-events: none.',
        code: `(function(){document.querySelectorAll('[style*="pointer-events: none"]').forEach(el=>{el.style.pointerEvents='auto';el.style.opacity='1';});})();`,
    },
    {
        id: 'all_in_one',
        name: '🚀 All-in-One (Enable/Unhide/Pointer)',
        desc: 'Combines enable-fields, unhide display:none, and re-enable pointer-events.',
        code: `(function(){document.querySelectorAll('[disabled],[readonly]').forEach(el=>{el.removeAttribute('disabled');el.removeAttribute('readonly');});document.querySelectorAll('[style*="display: none"]').forEach(el=>{el.style.display='block';});document.querySelectorAll('[style*="pointer-events: none"]').forEach(el=>{el.style.pointerEvents='auto';el.style.opacity='1';});alert('Disabled, readonly, and hidden elements are now active!');})();`,
    },
];

// OSINT bookmarklets sourced from https://tools.myosint.training/myosint_bookmarklets.html
// These are stored as full "javascript:" URL-encoded strings; the runner strips
// the prefix and decodes before injecting into the page.
const OSINT_BOOKMARKLETS = [
    {
        id: 'osint_domain_search',
        name: '🔍 OSINT Domain Search',
        desc: 'Opens WHOIS / DNS / reverse-IP lookup tabs for a domain you enter. (myosint.training)',
        encoded: true,
        code: `javascript:(function()%7Bvar%20MID%3D'__domainSearchModal'%3Bif(document.getElementById(MID))return%3Bvar%20modal%3Ddocument.createElement('div')%3Bmodal.id%3DMID%3Bmodal.style.cssText%3D'position%3Afixed%3Btop%3A60px%3Bleft%3A50%25%3Btransform%3AtranslateX(-50%25)%3Bz-index%3A999999%3Bbackground%3A%23022447%3Bborder%3A2px%20solid%20%23008BC4%3Bborder-radius%3A10px%3Bmax-width%3A92vw%3Bwidth%3Aclamp(360px%2C%2065vw%2C%20950px)%3Bmax-height%3A92vh%3Bfont-family%3AArial%2Csans-serif%3Bbox-shadow%3A0%208px%2032px%20rgba(0%2C0%2C0%2C0.6)%3Bdisplay%3Aflex%3Bflex-direction%3Acolumn%3B'%3Bvar%20hdr%3Ddocument.createElement('div')%3Bhdr.style.cssText%3D'background%3A%23008BC4%3Bpadding%3A10px%2016px%3Bborder-radius%3A8px%208px%200%200%3Btext-align%3Acenter%3Bcursor%3Agrab%3Buser-select%3Anone%3Bposition%3Arelative%3Bflex-shrink%3A0%3B'%3Bhdr.innerHTML%3D'%3Cdiv%20style%3D%22color%3A%23FFF%3Bfont-weight%3A600%3Bfont-size%3A14px%3B%22%3EDomain%20Search%20%3Cspan%20style%3D%22color%3A%2300E6F0%3Bfont-weight%3A400%3Bfont-size%3A11px%3B%22%3E(v2)%3C%2Fspan%3E%3C%2Fdiv%3E%3Cdiv%20style%3D%22color%3A%2300E6F0%3Bfont-size%3A9px%3Bmargin-top%3A2px%3B%22%3EGenerated%20by%20a%20bookmarklet%20from%20https%3A%2F%2Ftools.myosint.training%3C%2Fdiv%3E'%3Bvar%20cx%3Ddocument.createElement('span')%3Bcx.innerHTML%3D'%5Cu00d7'%3Bcx.style.cssText%3D'position%3Aabsolute%3Btop%3A6px%3Bright%3A12px%3Bcolor%3A%23FFF%3Bfont-size%3A22px%3Bcursor%3Apointer%3Bline-height%3A1%3B'%3Bcx.onclick%3Dfunction()%7Bmodal.remove()%3B%7D%3Bhdr.appendChild(cx)%3Bmodal.appendChild(hdr)%3Bvar%20content%3Ddocument.createElement('div')%3Bcontent.style.cssText%3D'padding%3A16px%2020px%3Boverflow-y%3Aauto%3Bflex%3A1%3B'%3Bvar%20sites%3D%5B%5B'Whoisology'%2C'https%3A%2F%2Fwhoisology.com%2F__DOMAIN__'%5D%2C%5B'BuiltWith'%2C'https%3A%2F%2Fbuiltwith.com%2F__DOMAIN__'%5D%2C%5B'DNSlytics'%2C'https%3A%2F%2Fsearch.dnslytics.com%2Fsearch%3Fd%3Ddomains%26q%3D__DOMAIN__'%5D%2C%5B'host.io'%2C'https%3A%2F%2Fhost.io%2F__DOMAIN__'%5D%2C%5B'DomainTools'%2C'https%3A%2F%2Fwhois.domaintools.com%2F__DOMAIN__'%5D%2C%5B'ViewDNS%20WHOIS'%2C'https%3A%2F%2Fviewdns.info%2Fwhois%2F%3Fdomain%3D__DOMAIN__'%5D%2C%5B'ViewDNS%20Reverse%20IP'%2C'https%3A%2F%2Fviewdns.info%2Freverseip%2F%3Fhost%3D__DOMAIN__%26t%3D1'%5D%2C%5B'ViewDNS%20IP%20History'%2C'https%3A%2F%2Fviewdns.info%2Fiphistory%2F%3Fdomain%3D__DOMAIN__'%5D%5D%3Bvar%20lbl%3Ddocument.createElement('div')%3Blbl.textContent%3D'Enter%20domain%20(no%20www%20or%20https%2C%20e.g.%20example.com)%3A'%3Blbl.style.cssText%3D'color%3A%23CCC%3Bfont-size%3A12px%3Bmargin-bottom%3A8px%3B'%3Bvar%20inp%3Ddocument.createElement('input')%3Binp.placeholder%3D'example.com'%3Binp.style.cssText%3D'width%3A100%25%3Bbox-sizing%3Aborder-box%3Bpadding%3A8px%3Bbackground%3A%23033556%3Bborder%3A1px%20solid%20%23008BC4%3Bborder-radius%3A4px%3Bcolor%3A%23FFF%3Bfont-size%3A13px%3Bfont-family%3ACourier%20New%2Cmonospace%3B'%3Bvar%20siteList%3Ddocument.createElement('div')%3BsiteList.style.cssText%3D'margin-top%3A10px%3Bcolor%3A%23CCC%3Bfont-size%3A11px%3B'%3BsiteList.innerHTML%3D'%3Cdiv%20style%3D%22color%3A%2300E6F0%3Bmargin-bottom%3A4px%3B%22%3EWill%20open%20'%2Bsites.length%2B'%20tabs%3A%3C%2Fdiv%3E'%2Bsites.map(function(s)%7Breturn%20'%3Cdiv%20style%3D%22padding%3A2px%200%3B%22%3E%E2%80%A2%20'%2Bs%5B0%5D%2B'%3C%2Fdiv%3E'%3B%7D).join('')%3Bvar%20btnRow%3Ddocument.createElement('div')%3BbtnRow.style.cssText%3D'margin-top%3A14px%3Btext-align%3Aright%3B'%3Bvar%20goBtn%3Ddocument.createElement('button')%3BgoBtn.textContent%3D'Launch%20All%20Tabs'%3BgoBtn.style.cssText%3D'background%3A%2300E6F0%3Bcolor%3A%23022447%3Bborder%3Anone%3Bpadding%3A8px%2016px%3Bborder-radius%3A4px%3Bcursor%3Apointer%3Bfont-weight%3A600%3Bfont-size%3A13px%3B'%3BgoBtn.onclick%3Dfunction()%7Bvar%20v%3Dinp.value.trim()%3Bif(!v)%7Balert('Please%20enter%20a%20domain.')%3Breturn%3B%7Dvar%20enc2%3DencodeURIComponent(v)%3Bsites.forEach(function(s)%7Bwindow.open(s%5B1%5D.replace(%2F__DOMAIN__%2Fg%2Cenc2)%2C'_blank'%2C'noopener')%3B%7D)%3Bmodal.remove()%3B%7D%3Binp.addEventListener('keydown'%2Cfunction(e)%7Bif(e.key%3D%3D%3D'Enter')goBtn.click()%3B%7D)%3BbtnRow.appendChild(goBtn)%3Bcontent.appendChild(lbl)%3Bcontent.appendChild(inp)%3Bcontent.appendChild(siteList)%3Bcontent.appendChild(btnRow)%3Bmodal.appendChild(content)%3Bdocument.body.appendChild(modal)%3Bvar%20dx%3D0%2Cdy%3D0%2Cdrag%3Dfalse%3Bhdr.addEventListener('mousedown'%2Cfunction(e)%7Bif(e.target%3D%3D%3Dcx)return%3Bdrag%3Dtrue%3Bvar%20r%3Dmodal.getBoundingClientRect()%3Bdx%3De.clientX-r.left%3Bdy%3De.clientY-r.top%3Bmodal.style.transform%3D'none'%3Bmodal.style.left%3Dr.left%2B'px'%3Bmodal.style.top%3Dr.top%2B'px'%3B%7D)%3Bdocument.addEventListener('mousemove'%2Cfunction(e)%7Bif(drag)%7Bmodal.style.left%3D(e.clientX-dx)%2B'px'%3Bmodal.style.top%3D(e.clientY-dy)%2B'px'%3B%7D%7D)%3Bdocument.addEventListener('mouseup'%2Cfunction()%7Bdrag%3Dfalse%3B%7D)%3BsetTimeout(function()%7Binp.focus()%3B%7D%2C50)%3B%7D)()%3B`,
    },
    {
        id: 'osint_us_name_search',
        name: '🔍 OSINT US Name Search',
        desc: 'Opens people-search lookup tabs (TruePeopleSearch, Spokeo, WhitePages, …) for a US name. (myosint.training)',
        encoded: true,
        code: `javascript:(function()%7Bvar%20MID%3D'__usNameSearchModal'%3Bif(document.getElementById(MID))return%3Bvar%20modal%3Ddocument.createElement('div')%3Bmodal.id%3DMID%3Bmodal.style.cssText%3D'position%3Afixed%3Btop%3A60px%3Bleft%3A50%25%3Btransform%3AtranslateX(-50%25)%3Bz-index%3A999999%3Bbackground%3A%23022447%3Bborder%3A2px%20solid%20%23008BC4%3Bborder-radius%3A10px%3Bmax-width%3A92vw%3Bwidth%3Aclamp(360px%2C%2065vw%2C%20950px)%3Bmax-height%3A92vh%3Bfont-family%3AArial%2Csans-serif%3Bbox-shadow%3A0%208px%2032px%20rgba(0%2C0%2C0%2C0.6)%3Bdisplay%3Aflex%3Bflex-direction%3Acolumn%3B'%3Bvar%20hdr%3Ddocument.createElement('div')%3Bhdr.style.cssText%3D'background%3A%23008BC4%3Bpadding%3A10px%2016px%3Bborder-radius%3A8px%208px%200%200%3Btext-align%3Acenter%3Bcursor%3Agrab%3Buser-select%3Anone%3Bposition%3Arelative%3Bflex-shrink%3A0%3B'%3Bhdr.innerHTML%3D'%3Cdiv%20style%3D%22color%3A%23FFF%3Bfont-weight%3A600%3Bfont-size%3A14px%3B%22%3EUS%20Name%20Search%20%3Cspan%20style%3D%22color%3A%2300E6F0%3Bfont-weight%3A400%3Bfont-size%3A11px%3B%22%3E(v2)%3C%2Fspan%3E%3C%2Fdiv%3E%3Cdiv%20style%3D%22color%3A%2300E6F0%3Bfont-size%3A9px%3Bmargin-top%3A2px%3B%22%3EGenerated%20by%20a%20bookmarklet%20from%20https%3A%2F%2Ftools.myosint.training%3C%2Fdiv%3E'%3Bvar%20cx%3Ddocument.createElement('span')%3Bcx.innerHTML%3D'%5Cu00d7'%3Bcx.style.cssText%3D'position%3Aabsolute%3Btop%3A6px%3Bright%3A12px%3Bcolor%3A%23FFF%3Bfont-size%3A22px%3Bcursor%3Apointer%3Bline-height%3A1%3B'%3Bcx.onclick%3Dfunction()%7Bmodal.remove()%3B%7D%3Bhdr.appendChild(cx)%3Bmodal.appendChild(hdr)%3Bvar%20content%3Ddocument.createElement('div')%3Bcontent.style.cssText%3D'padding%3A16px%2020px%3Boverflow-y%3Aauto%3Bflex%3A1%3B'%3Bvar%20sites%3D%5B%5B'TruePeopleSearch'%2C'https%3A%2F%2Fwww.truepeoplesearch.com%2Fresults%3Fname%3D__FN__%2B__LN__%26citystatezip%3D__ST__'%5D%2C%5B'FastPeopleSearch'%2C'https%3A%2F%2Fwww.fastpeoplesearch.com%2Fname%2F__FN__-__LN___ST__'%5D%2C%5B'FamilyTreeNow'%2C'https%3A%2F%2Fwww.familytreenow.com%2Fsearch%2Fgenealogy%2Fresults%3Ffirst%3D__FN__%26last%3D__LN__%26citystatezip%3D__ST__'%5D%2C%5B'SearchPeopleFree'%2C'https%3A%2F%2Fwww.searchpeoplefree.com%2Ffind%2F__FN__-__LN__%2F__ST__'%5D%2C%5B'Spokeo'%2C'https%3A%2F%2Fwww.spokeo.com%2F__FN__-__LN__%2F__ST__'%5D%2C%5B'WhitePages'%2C'https%3A%2F%2Fwww.whitepages.com%2Fname%2F__FN__-__LN__%2F__ST__'%5D%2C%5B'ThatsThem'%2C'https%3A%2F%2Fthatsthem.com%2Fname%2F__FN__-__LN__%2F__ST__'%5D%2C%5B'CyberBackgroundChecks'%2C'https%3A%2F%2Fwww.cyberbackgroundchecks.com%2Fpeople%2F__FN__-__LN__%2F__ST__'%5D%5D%3Bfunction%20mkField(label%2Cph)%7Bvar%20wrap%3Ddocument.createElement('div')%3Bwrap.style.cssText%3D'margin-bottom%3A10px%3B'%3Bvar%20lbl%3Ddocument.createElement('div')%3Blbl.textContent%3Dlabel%3Blbl.style.cssText%3D'color%3A%23CCC%3Bfont-size%3A12px%3Bmargin-bottom%3A4px%3B'%3Bvar%20inp%3Ddocument.createElement('input')%3Binp.placeholder%3Dph%3Binp.style.cssText%3D'width%3A100%25%3Bbox-sizing%3Aborder-box%3Bpadding%3A8px%3Bbackground%3A%23033556%3Bborder%3A1px%20solid%20%23008BC4%3Bborder-radius%3A4px%3Bcolor%3A%23FFF%3Bfont-size%3A13px%3Bfont-family%3ACourier%20New%2Cmonospace%3B'%3Bwrap.appendChild(lbl)%3Bwrap.appendChild(inp)%3Bcontent.appendChild(wrap)%3Breturn%20inp%3B%7Dvar%20inpFirst%3DmkField('First%20Name%3A'%2C'Jane')%3Bvar%20inpLast%3DmkField('Last%20Name%3A'%2C'Smith')%3Bvar%20inpState%3DmkField('US%20State%20(abbreviation%20or%20full%20name)%3A'%2C'CA')%3Bvar%20siteList%3Ddocument.createElement('div')%3BsiteList.style.cssText%3D'margin-top%3A6px%3Bcolor%3A%23CCC%3Bfont-size%3A11px%3B'%3BsiteList.innerHTML%3D'%3Cdiv%20style%3D%22color%3A%2300E6F0%3Bmargin-bottom%3A4px%3B%22%3EWill%20open%20'%2Bsites.length%2B'%20tabs%3A%3C%2Fdiv%3E'%2Bsites.map(function(s)%7Breturn%20'%3Cdiv%20style%3D%22padding%3A2px%200%3B%22%3E%E2%80%A2%20'%2Bs%5B0%5D%2B'%3C%2Fdiv%3E'%3B%7D).join('')%3Bcontent.appendChild(siteList)%3Bvar%20btnRow%3Ddocument.createElement('div')%3BbtnRow.style.cssText%3D'margin-top%3A14px%3Btext-align%3Aright%3B'%3Bvar%20goBtn%3Ddocument.createElement('button')%3BgoBtn.textContent%3D'Launch%20All%20Tabs'%3BgoBtn.style.cssText%3D'background%3A%2300E6F0%3Bcolor%3A%23022447%3Bborder%3Anone%3Bpadding%3A8px%2016px%3Bborder-radius%3A4px%3Bcursor%3Apointer%3Bfont-weight%3A600%3Bfont-size%3A13px%3B'%3BgoBtn.onclick%3Dfunction()%7Bvar%20fn%3DinpFirst.value.trim()%2Cln%3DinpLast.value.trim()%2Cst%3DinpState.value.trim()%3Bif(!fn)%7Balert('Please%20enter%20a%20first%20name.')%3Breturn%3B%7Dvar%20efn%3DencodeURIComponent(fn)%2Celn%3DencodeURIComponent(ln)%2Cest%3DencodeURIComponent(st)%3Bsites.forEach(function(s)%7Bwindow.open(s%5B1%5D.replace(%2F__FN__%2Fg%2Cefn).replace(%2F__LN__%2Fg%2Celn).replace(%2F__ST__%2Fg%2Cest)%2C'_blank'%2C'noopener')%3B%7D)%3Bmodal.remove()%3B%7D%3BinpState.addEventListener('keydown'%2Cfunction(e)%7Bif(e.key%3D%3D%3D'Enter')goBtn.click()%3B%7D)%3BbtnRow.appendChild(goBtn)%3Bcontent.appendChild(btnRow)%3Bmodal.appendChild(content)%3Bdocument.body.appendChild(modal)%3Bvar%20dx%3D0%2Cdy%3D0%2Cdrag%3Dfalse%3Bhdr.addEventListener('mousedown'%2Cfunction(e)%7Bif(e.target%3D%3D%3Dcx)return%3Bdrag%3Dtrue%3Bvar%20r%3Dmodal.getBoundingClientRect()%3Bdx%3De.clientX-r.left%3Bdy%3De.clientY-r.top%3Bmodal.style.transform%3D'none'%3Bmodal.style.left%3Dr.left%2B'px'%3Bmodal.style.top%3Dr.top%2B'px'%3B%7D)%3Bdocument.addEventListener('mousemove'%2Cfunction(e)%7Bif(drag)%7Bmodal.style.left%3D(e.clientX-dx)%2B'px'%3Bmodal.style.top%3D(e.clientY-dy)%2B'px'%3B%7D%7D)%3Bdocument.addEventListener('mouseup'%2Cfunction()%7Bdrag%3Dfalse%3B%7D)%3BsetTimeout(function()%7BinpFirst.focus()%3B%7D%2C50)%3B%7D)()%3B`,
    },
    {
        id: 'osint_us_phone_search',
        name: '🔍 OSINT US Phone Search',
        desc: 'Opens reverse phone lookup tabs (TruePeopleSearch, Nuwber, ThatsThem, …) for a US number. (myosint.training)',
        encoded: true,
        code: `javascript:(function()%7Bvar%20MID%3D'__usPhoneSearchModal'%3Bif(document.getElementById(MID))return%3Bvar%20modal%3Ddocument.createElement('div')%3Bmodal.id%3DMID%3Bmodal.style.cssText%3D'position%3Afixed%3Btop%3A60px%3Bleft%3A50%25%3Btransform%3AtranslateX(-50%25)%3Bz-index%3A999999%3Bbackground%3A%23022447%3Bborder%3A2px%20solid%20%23008BC4%3Bborder-radius%3A10px%3Bmax-width%3A92vw%3Bwidth%3Aclamp(360px%2C%2065vw%2C%20950px)%3Bmax-height%3A92vh%3Bfont-family%3AArial%2Csans-serif%3Bbox-shadow%3A0%208px%2032px%20rgba(0%2C0%2C0%2C0.6)%3Bdisplay%3Aflex%3Bflex-direction%3Acolumn%3B'%3Bvar%20hdr%3Ddocument.createElement('div')%3Bhdr.style.cssText%3D'background%3A%23008BC4%3Bpadding%3A10px%2016px%3Bborder-radius%3A8px%208px%200%200%3Btext-align%3Acenter%3Bcursor%3Agrab%3Buser-select%3Anone%3Bposition%3Arelative%3Bflex-shrink%3A0%3B'%3Bhdr.innerHTML%3D'%3Cdiv%20style%3D%22color%3A%23FFF%3Bfont-weight%3A600%3Bfont-size%3A14px%3B%22%3EUS%20Phone%20Search%20%3Cspan%20style%3D%22color%3A%2300E6F0%3Bfont-weight%3A400%3Bfont-size%3A11px%3B%22%3E(v2)%3C%2Fspan%3E%3C%2Fdiv%3E%3Cdiv%20style%3D%22color%3A%2300E6F0%3Bfont-size%3A9px%3Bmargin-top%3A2px%3B%22%3EGenerated%20by%20a%20bookmarklet%20from%20https%3A%2F%2Ftools.myosint.training%3C%2Fdiv%3E'%3Bvar%20cx%3Ddocument.createElement('span')%3Bcx.innerHTML%3D'%5Cu00d7'%3Bcx.style.cssText%3D'position%3Aabsolute%3Btop%3A6px%3Bright%3A12px%3Bcolor%3A%23FFF%3Bfont-size%3A22px%3Bcursor%3Apointer%3Bline-height%3A1%3B'%3Bcx.onclick%3Dfunction()%7Bmodal.remove()%3B%7D%3Bhdr.appendChild(cx)%3Bmodal.appendChild(hdr)%3Bvar%20content%3Ddocument.createElement('div')%3Bcontent.style.cssText%3D'padding%3A16px%2020px%3Boverflow-y%3Aauto%3Bflex%3A1%3B'%3Bvar%20sites%3D%5B%5B'TruePeopleSearch'%2C'https%3A%2F%2Fwww.truepeoplesearch.com%2Fresults%3Fphoneno%3D(__AC__)__PR__-__L4__'%5D%2C%5B'FastPeopleSearch'%2C'https%3A%2F%2Fwww.fastpeoplesearch.com%2F__AC__-__PR__-__L4__'%5D%2C%5B'Nuwber'%2C'https%3A%2F%2Fnuwber.com%2Fsearch%2Fphone%3Fphone%3D__AC____PR____L4__'%5D%2C%5B'WhoSENo'%2C'https%3A%2F%2Fwww.whoseno.com%2FUS%2F__AC____PR____L4__'%5D%2C%5B'PeopleSearchNow'%2C'https%3A%2F%2Fwww.peoplesearchnow.com%2Fphone%2F__AC__-__PR__-__L4__'%5D%2C%5B'RevealName'%2C'https%3A%2F%2Fwww.revealname.com%2F__AC__-__PR__-__L4__'%5D%2C%5B'SearchPeopleFree'%2C'https%3A%2F%2Fwww.searchpeoplefree.com%2Fphone-lookup%2F__AC__-__PR__-__L4__'%5D%2C%5B'Sync.me'%2C'https%3A%2F%2Fsync.me%2Fsearch%2F%3Fnumber%3D1__AC____PR____L4__'%5D%2C%5B'ThatsThem'%2C'https%3A%2F%2Fthatsthem.com%2Fphone%2F__AC__-__PR__-__L4__'%5D%2C%5B'AdvancedBGChecks'%2C'https%3A%2F%2Fwww.advancedbackgroundchecks.com%2F__AC__-__PR__-__L4__'%5D%2C%5B'USPhoneBook'%2C'https%3A%2F%2Fwww.usphonebook.com%2F__AC__-__PR__-__L4__'%5D%2C%5B'CyberBGChecks'%2C'https%3A%2F%2Fwww.cyberbackgroundchecks.com%2Fphone%2F__AC__-__PR__-__L4__'%5D%5D%3Bvar%20ph%3Ddocument.createElement('div')%3Bph.style.cssText%3D'color%3A%23CCC%3Bfont-size%3A12px%3Bmargin-bottom%3A10px%3B'%3Bph.textContent%3D'Enter%20phone%20number%20in%203%20parts%3A'%3Bcontent.appendChild(ph)%3Bvar%20fieldRow%3Ddocument.createElement('div')%3BfieldRow.style.cssText%3D'display%3Aflex%3Bgap%3A8px%3Bmargin-bottom%3A6px%3B'%3Bfunction%20mkTel(lbl%2Cph2%2Cmaxl)%7Bvar%20wrap%3Ddocument.createElement('div')%3Bwrap.style.cssText%3D'flex%3A1%3B'%3Bvar%20l%3Ddocument.createElement('div')%3Bl.textContent%3Dlbl%3Bl.style.cssText%3D'color%3A%23CCC%3Bfont-size%3A11px%3Bmargin-bottom%3A4px%3B'%3Bvar%20inp%3Ddocument.createElement('input')%3Binp.placeholder%3Dph2%3Binp.maxLength%3Dmaxl%3Binp.type%3D'tel'%3Binp.style.cssText%3D'width%3A100%25%3Bbox-sizing%3Aborder-box%3Bpadding%3A8px%3Bbackground%3A%23033556%3Bborder%3A1px%20solid%20%23008BC4%3Bborder-radius%3A4px%3Bcolor%3A%23FFF%3Bfont-size%3A13px%3Bfont-family%3ACourier%20New%2Cmonospace%3Btext-align%3Acenter%3B'%3Bwrap.appendChild(l)%3Bwrap.appendChild(inp)%3BfieldRow.appendChild(wrap)%3Breturn%20inp%3B%7Dvar%20inpAc%3DmkTel('Area%20Code'%2C'555'%2C3)%3Bvar%20inpPr%3DmkTel('Prefix'%2C'867'%2C3)%3Bvar%20inpL4%3DmkTel('Last%204'%2C'5309'%2C4)%3Bcontent.appendChild(fieldRow)%3Bvar%20siteList%3Ddocument.createElement('div')%3BsiteList.style.cssText%3D'margin-top%3A6px%3Bcolor%3A%23CCC%3Bfont-size%3A11px%3B'%3BsiteList.innerHTML%3D'%3Cdiv%20style%3D%22color%3A%2300E6F0%3Bmargin-bottom%3A4px%3B%22%3EWill%20open%20'%2Bsites.length%2B'%20tabs%3A%3C%2Fdiv%3E'%2Bsites.map(function(s)%7Breturn%20'%3Cdiv%20style%3D%22padding%3A2px%200%3B%22%3E%E2%80%A2%20'%2Bs%5B0%5D%2B'%3C%2Fdiv%3E'%3B%7D).join('')%3Bcontent.appendChild(siteList)%3Bvar%20btnRow%3Ddocument.createElement('div')%3BbtnRow.style.cssText%3D'margin-top%3A14px%3Btext-align%3Aright%3B'%3Bvar%20goBtn%3Ddocument.createElement('button')%3BgoBtn.textContent%3D'Launch%20All%20Tabs'%3BgoBtn.style.cssText%3D'background%3A%2300E6F0%3Bcolor%3A%23022447%3Bborder%3Anone%3Bpadding%3A8px%2016px%3Bborder-radius%3A4px%3Bcursor%3Apointer%3Bfont-weight%3A600%3Bfont-size%3A13px%3B'%3BgoBtn.onclick%3Dfunction()%7Bvar%20ac%3DinpAc.value.trim()%2Cpr%3DinpPr.value.trim()%2Cl4%3DinpL4.value.trim()%3Bif(ac.length!%3D%3D3%7C%7Cpr.length!%3D%3D3%7C%7Cl4.length!%3D%3D4)%7Balert('Please%20enter%20valid%203-3-4%20phone%20digits.')%3Breturn%3B%7Dsites.forEach(function(s)%7Bwindow.open(s%5B1%5D.replace(%2F__AC__%2Fg%2Cac).replace(%2F__PR__%2Fg%2Cpr).replace(%2F__L4__%2Fg%2Cl4)%2C'_blank'%2C'noopener')%3B%7D)%3Bmodal.remove()%3B%7D%3BinpL4.addEventListener('keydown'%2Cfunction(e)%7Bif(e.key%3D%3D%3D'Enter')goBtn.click()%3B%7D)%3BbtnRow.appendChild(goBtn)%3Bcontent.appendChild(btnRow)%3Bmodal.appendChild(content)%3Bdocument.body.appendChild(modal)%3Bvar%20dx%3D0%2Cdy%3D0%2Cdrag%3Dfalse%3Bhdr.addEventListener('mousedown'%2Cfunction(e)%7Bif(e.target%3D%3D%3Dcx)return%3Bdrag%3Dtrue%3Bvar%20r%3Dmodal.getBoundingClientRect()%3Bdx%3De.clientX-r.left%3Bdy%3De.clientY-r.top%3Bmodal.style.transform%3D'none'%3Bmodal.style.left%3Dr.left%2B'px'%3Bmodal.style.top%3Dr.top%2B'px'%3B%7D)%3Bdocument.addEventListener('mousemove'%2Cfunction(e)%7Bif(drag)%7Bmodal.style.left%3D(e.clientX-dx)%2B'px'%3Bmodal.style.top%3D(e.clientY-dy)%2B'px'%3B%7D%7D)%3Bdocument.addEventListener('mouseup'%2Cfunction()%7Bdrag%3Dfalse%3B%7D)%3BsetTimeout(function()%7BinpAc.focus()%3B%7D%2C50)%3B%7D)()%3B`,
    },
];

const OSINT_SOURCE_URL = 'https://tools.myosint.training/myosint_bookmarklets.html';

const CUSTOM_BOOKMARKLETS_KEY = 'greytab_custom_bookmarklets_v1';

// ── Helpers ────────────────────────────────────────────────────────

function bookmarkletStorage() {
    return new Promise((resolve) => {
        if (!chrome?.storage?.local) { resolve({}); return; }
        chrome.storage.local.get(CUSTOM_BOOKMARKLETS_KEY, (res) => {
            resolve(res?.[CUSTOM_BOOKMARKLETS_KEY] || {});
        });
    });
}

function saveBookmarkletStorage(data) {
    return new Promise((resolve) => {
        if (!chrome?.storage?.local) { resolve(); return; }
        chrome.storage.local.set({ [CUSTOM_BOOKMARKLETS_KEY]: data || {} }, () => resolve());
    });
}

// Fetch the active tab so we can show the target and execute on it.
function getActiveTab() {
    return new Promise((resolve) => {
        if (!chrome?.tabs?.query) { resolve(null); return; }
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            resolve(tabs && tabs[0] ? tabs[0] : null);
        });
    });
}

// Execute a bookmarklet's code on the active tab. Returns true on success.
async function runBookmarkletOnActiveTab(code) {
    const tab = await getActiveTab();
    if (!tab || !tab.id) {
        alert('No active tab found.');
        return false;
    }
    // chrome:// and extension pages can't be injected; guard against that.
    const url = tab.url || '';
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        alert('Bookmarklets can only run on http(s:// pages (not chrome:// or extension pages).');
        return false;
    }
    if (!chrome?.scripting?.executeScript) {
        alert('chrome.scripting is not available. Reload the extension after updating permissions.');
        return false;
    }
    try {
        const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: (src) => {
                // Eval the bookmarklet body in the page's context.
                try { (0, eval)(src); return { ok: true }; }
                catch (e) { return { ok: false, error: e.message }; }
            },
            args: [code],
            world: 'MAIN',
        });
        if (!results?.length || !results[0].result?.ok) throw new Error(results?.[0]?.result?.error || 'The page blocked this bookmarklet.');
        return true;
    } catch (e) {
        alert('Failed to run bookmarklet: ' + (e?.message || e));
        return false;
    }
}

// ── Rendering ──────────────────────────────────────────────────────

function renderBookmarkletRow(item, isCustom) {
    const card = document.createElement('div');
    card.className = 'settings-tool-card';
    card.innerHTML = `
        <div class="settings-tool-card__info">
            <div class="settings-tool-card__name">${escHtml(item.name)}</div>
            <div class="settings-tool-card__desc">${escHtml(item.desc || '')}</div>
        </div>
        <div class="settings-tool-card__actions">
            <button class="btn btn--ghost btn--xs" data-bm-run="${escHtml(item.id)}" title="Run on active tab">
                <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none">
                    <polygon points="5 3 19 12 5 21 5 3"></polygon>
                </svg>
                Run
            </button>
            <button class="btn btn--ghost btn--xs" data-bm-copy="${escHtml(item.id)}" title="Copy bookmarklet URL">
                <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
                <span class="bm-copy-label">Copy</span>
            </button>
            ${isCustom ? `<button class="btn--icon-danger" data-bm-delete="${escHtml(item.id)}" title="Delete bookmarklet">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                    <polyline points="3 6 5 6 21 6"></polyline>
                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                </svg>
            </button>` : ''}
        </div>
    `;
    return card;
}

let _bookmarkletsCache = { builtin: [], osint: [], custom: [] };

async function loadBookmarklets() {
    const host = document.getElementById('bookmarklets-list');
    if (!host) return;

    const custom = await bookmarkletStorage();
    const customList = Object.values(custom || {});

    _bookmarkletsCache.builtin = BUILTIN_BOOKMARKLETS.slice();
    _bookmarkletsCache.osint = OSINT_BOOKMARKLETS.slice();
    _bookmarkletsCache.custom = customList;

    host.innerHTML = '';

    const builtinHeader = document.createElement('div');
    builtinHeader.className = 'section__header';
    builtinHeader.style.padding = '0 0 0.4rem 0';
    builtinHeader.innerHTML = '<h4 style="margin:0;">Built-in</h4>';
    host.appendChild(builtinHeader);

    for (const item of BUILTIN_BOOKMARKLETS) {
        host.appendChild(renderBookmarkletRow(item, false));
    }

    const osintHeader = document.createElement('div');
    osintHeader.className = 'section__header';
    osintHeader.style.padding = '0.75rem 0 0.4rem 0';
    osintHeader.innerHTML = `<h4 style="margin:0;">OSINT <span class="badge">${OSINT_BOOKMARKLETS.length}</span>
        <a href="${OSINT_SOURCE_URL}" target="_blank" rel="noopener" class="bm-source-link" title="Full collection at tools.myosint.training">more ↗</a></h4>`;
    host.appendChild(osintHeader);

    for (const item of OSINT_BOOKMARKLETS) {
        host.appendChild(renderBookmarkletRow(item, false));
    }

    const customHeader = document.createElement('div');
    customHeader.className = 'section__header';
    customHeader.style.padding = '0.75rem 0 0.4rem 0';
    customHeader.innerHTML = `<h4 style="margin:0;">Custom <span class="badge">${customList.length}</span></h4>`;
    host.appendChild(customHeader);

    if (customList.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.innerHTML = '<span class="empty-state__text">No custom bookmarklets. Add one below.</span>';
        host.appendChild(empty);
    } else {
        for (const item of customList) {
            host.appendChild(renderBookmarkletRow(item, true));
        }
    }
}

// Resolve a bookmarklet id → code from the cache.
function findBookmarklet(id) {
    return _bookmarkletsCache.builtin.find((b) => b.id === id)
        || _bookmarkletsCache.osint.find((b) => b.id === id)
        || _bookmarkletsCache.custom.find((b) => b.id === id);
}

// Normalize stored code to raw JS. OSINT entries are kept as full
// "javascript:" URL-encoded strings and are decoded here before injection.
function decodeBookmarkletCode(code) {
    if (!code) return '';
    let s = code;
    if (s.toLowerCase().startsWith('javascript:')) {
        s = s.slice('javascript:'.length);
        try { s = decodeURIComponent(s); } catch { /* keep raw */ }
    }
    return s;
}

// Build a "javascript:" URL for copy-to-clipboard.
function toBookmarkletUrl(code) {
    // If the stored code is already a full javascript: URL (encoded), use it as-is.
    if (typeof code === 'string' && code.toLowerCase().startsWith('javascript:')) return code;
    return 'javascript:' + encodeURIComponent(code);
}

// ── Event wiring ───────────────────────────────────────────────────

document.getElementById('bookmarklets-list')?.addEventListener('click', async (e) => {
    const runBtn = e.target.closest('[data-bm-run]');
    const copyBtn = e.target.closest('[data-bm-copy]');
    const delBtn = e.target.closest('[data-bm-delete]');

    if (runBtn) {
        const id = runBtn.dataset.bmRun;
        const item = findBookmarklet(id);
        if (item) await runBookmarkletOnActiveTab(decodeBookmarkletCode(item.code));
        return;
    }
    if (copyBtn) {
        const id = copyBtn.dataset.bmCopy;
        const item = findBookmarklet(id);
        if (item) {
            try {
                await navigator.clipboard.writeText(toBookmarkletUrl(item.code));
                const label = copyBtn.querySelector('.bm-copy-label') || copyBtn;
                const orig = label.textContent;
                label.textContent = '✓ Copied';
                copyBtn.classList.add('btn--success');
                setTimeout(() => { label.textContent = orig; copyBtn.classList.remove('btn--success'); }, 1200);
            } catch {
                alert('Copy failed: ' + toBookmarkletUrl(item.code));
            }
        }
        return;
    }
    if (delBtn) {
        const id = delBtn.dataset.bmDelete;
        if (!confirm('Delete this custom bookmarklet?')) return;
        const data = await bookmarkletStorage();
        delete data[id];
        await saveBookmarkletStorage(data);
        loadBookmarklets();
        return;
    }
});

document.getElementById('btn-bm-save-custom')?.addEventListener('click', async () => {
    const nameInput = document.getElementById('bm-custom-name');
    const codeInput = document.getElementById('bm-custom-code');
    const status = document.getElementById('bm-custom-status');
    const name = (nameInput?.value || '').trim();
    let code = (codeInput?.value || '').trim();
    if (!name || !code) {
        if (status) { status.textContent = 'Name and code are required.'; status.style.color = 'var(--danger)'; }
        return;
    }
    // Allow the user to paste a full "javascript:..." URL — strip it.
    if (code.toLowerCase().startsWith('javascript:')) {
        try { code = decodeURIComponent(code.slice('javascript:'.length)); }
        catch { code = code.slice('javascript:'.length); }
    }
    const data = await bookmarkletStorage();
    const id = 'custom_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
    data[id] = { id, name, desc: 'Custom bookmarklet', code };
    await saveBookmarkletStorage(data);
    if (nameInput) nameInput.value = '';
    if (codeInput) codeInput.value = '';
    if (status) { status.textContent = '✓ Saved'; status.style.color = 'var(--success)'; setTimeout(() => { status.textContent = ''; }, 1500); }
    loadBookmarklets();
});

document.getElementById('btn-bm-run-custom')?.addEventListener('click', async () => {
    const codeInput = document.getElementById('bm-custom-code');
    let code = (codeInput?.value || '').trim();
    if (!code) {
        alert('Enter bookmarklet code first.');
        return;
    }
    if (code.toLowerCase().startsWith('javascript:')) {
        try { code = decodeURIComponent(code.slice('javascript:'.length)); }
        catch { code = code.slice('javascript:'.length); }
    }
    await runBookmarkletOnActiveTab(code);
});

document.getElementById('btn-bm-refresh-tab')?.addEventListener('click', updateBookmarkletTargetInfo);

async function updateBookmarkletTargetInfo() {
    const info = document.getElementById('bookmarklet-target-info');
    if (!info) return;
    const tab = await getActiveTab();
    if (!tab) {
        info.textContent = 'No active tab.';
        return;
    }
    const url = tab.url || '';
    const canRun = url.startsWith('http://') || url.startsWith('https://');
    info.textContent = canRun
        ? `Active tab: ${tab.title || '(no title)'} — ${url}`
        : `Active tab is not an http(s) page — bookmarklets can't run here.`;
    info.style.color = canRun ? 'var(--text-muted)' : 'var(--danger)';
}

// Load when the bookmarklets tab is opened.
const _bmTabBtn = document.querySelector('.tab[data-tab="bookmarklets"]');
if (_bmTabBtn) {
    _bmTabBtn.addEventListener('click', () => {
        loadBookmarklets();
        updateBookmarkletTargetInfo();
    });
}
