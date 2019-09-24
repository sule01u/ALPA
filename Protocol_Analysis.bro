# dns telnet pop3 snmp  Netflow  sip imap  ((smtp http ftp))

const telnet_ports = { 23/tcp };
const pop3_ports = { 110/tcp };
const imap_ports = { 143/tcp };
const netflow_ports = { 12345/udp };

global routerID:string;

event bro_init() {
    routerID = "123456";
    Analyzer::register_for_ports(Analyzer::ANALYZER_TELNET, telnet_ports);
    Analyzer::register_for_ports(Analyzer::ANALYZER_POP3, pop3_ports);
    Analyzer::register_for_ports(Analyzer::ANALYZER_IMAP, imap_ports);
    Analyzer::register_for_ports(Analyzer::ANALYZER_NETFLOW, netflow_ports); 
}



type recordRequest: record {
    strSrcIp: string &optional;
    strDstIp: string &optional;
    strSrcPort: string &optional;
    strDstPort: string &optional;
    strURI: string &optional;
    tableHeaders: table[string] of string &optional;
    ifWriteFile: bool &optional;
    ifWriteTempData: bool &optional;
    strTempData: string &optional;
    strFileName: string &optional;
    strTempFileName: string &optional;
    strHTTPMethod: string &optional;
    intContentSize: count &optional;
};


type recordSMTPAttachmentFile: record {
    strFileName: string &optional;
    strSrcIp: string &optional;
    strDstIp: string &optional;
    strSrcPort: string &optional;
    strDstPort: string &optional;
    strConnectionUid: string &optional;
    strTempFileName: string &optional;
};

type recordMIME: record {
    strMailTo: string &optional;
    strMailFrom: string &optional;
    strMailCC: string &optional;
    strMailSubject:string &optional;
    ifTls: bool &optional;
    strTempData: string &optional;
    ifAttachmentBegin: bool &optional;
    strSrcIp: string &optional;
    strDstIp: string &optional;
    strSrcPort: string &optional;
    strDstPort: string &optional;
    strConnectionUid: string &optional;
};


type recordFTPAttachmentFile: record {
    strFileName: string &optional;
    strSrcIp: string &optional;
    strDstIp: string &optional;
    strSrcPort: string &optional;
    strDstPort: string &optional;
    strTempFileName: string &optional;
};


type recordFTPAttachmentMsg: record {
    strSrcIp: string &optional;
    strDstIp: string &optional;
    strSrcPort: string &optional;
    strDstPort: string &optional;
    strUser: string &optional;
    strPass: string &optional;
    strPortDstIp: string &optional;
    strPortDstPort: string &optional;
    boolPortState: bool &optional;
    strFtpCommand: string &optional;
    strPasvDstIp: string &optional;
    strPasvDstPort: string &optional;
};

global gtableFTPAttachmentMsg: table[string] of recordFTPAttachmentMsg &create_expire=30min;
global gtableFTPAttachmentFile: table[string] of recordFTPAttachmentFile &create_expire=30min;

global gtableRecordMime: table[string] of recordMIME &create_expire=30min;
global gtableSmtpAttachmentFile: table[string] of recordSMTPAttachmentFile &create_expire=30min;

global gtableRequest: table[string,time] of recordRequest &create_expire=30min;


redef http_entity_data_delivery_size = 1000000; 
redef use_conn_size_analyzer = T;
redef FTP::default_capture_password = T;


event http_request(c:connection,method:string,original_URI:string,unescaped_URI:string,version:string) {
    if (method == "POST") {
        gtableRequest[c$uid,c$http$ts] = [$ifWriteFile = T,
                                            $strURI = unescaped_URI,
                                            $ifWriteTempData = F,
                                            $strTempData = "",
                                            $strFileName = "",
                                            $strTempFileName = "",
                                            $intContentSize = 0,
                                            $strHTTPMethod = "POST"];
    }
}

function extract_cid(data: string, kv_splitter: pattern): string
    {
    local key_vec: vector of string = vector();
    local parts = split_string(data, kv_splitter);
    for ( part_index in parts )
        {
        local key_val = split_string1(parts[part_index], /=/);
        if ( 0 in key_val )
            key_vec[|key_vec|] = key_val[0];
            if (strstr(key_val[0],"cid") != 0) {
                return key_val[1];
            }
        }
    return "nothings";
}

event http_all_headers(c:connection,is_orig:bool,hlist:mime_header_list) {
    if ( !is_orig) {
        return;
    }
    if ([c$uid,c$http$ts] in gtableRequest) {
        if (gtableRequest[c$uid,c$http$ts]?$tableHeaders) {
            for ( h in hlist) {
                gtableRequest[c$uid,c$http$ts]$tableHeaders[hlist[h]$name] = hlist[h]$value;
            }
            if ("CONTENT-LENGTH" in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                gtableRequest[c$uid,c$http$ts]$intContentSize = to_count(gtableRequest[c$uid,c$http$ts]$tableHeaders["CONTENT-LENGTH"]);
                if (gtableRequest[c$uid,c$http$ts]$intContentSize <= 2048) {
                    gtableRequest[c$uid,c$http$ts]$ifWriteTempData = T;

                }
            }
            if ("MAIL-UPLOAD-MODTIME" in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                    gtableRequest[c$uid,c$http$ts]$ifWriteTempData = T;
                    
                    gtableRequest[c$uid,c$http$ts]$strTempFileName = fmt("/opt/uploadFile/%s/%s_%s",strftime("%Y-%m-%d",current_time()),gtableRequest[c$uid,c$http$ts]$tableHeaders["MAIL-UPLOAD-MODTIME"],extract_cid(gtableRequest[c$uid,c$http$ts]$strURI,/&/));
            }
        } else {
            local tableTmpHeaders: table[string] of string;
            for ( h in hlist) {
                tableTmpHeaders[hlist[h]$name] = hlist[h]$value;
            }

            gtableRequest[c$uid,c$http$ts]$tableHeaders = copy(tableTmpHeaders);
            if ("MAIL-UPLOAD-MODTIME" in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                gtableRequest[c$uid,c$http$ts]$ifWriteTempData = T;
                    gtableRequest[c$uid,c$http$ts]$strTempFileName = fmt("/opt/uploadFile/%s/%s_%s",strftime("%Y-%m-%d",current_time()),gtableRequest[c$uid,c$http$ts]$tableHeaders["MAIL-UPLOAD-MODTIME"],extract_cid(gtableRequest[c$uid,c$http$ts]$strURI,/&/));
            }
            if ("CONTENT-LENGTH" in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                gtableRequest[c$uid,c$http$ts]$intContentSize = to_count(gtableRequest[c$uid,c$http$ts]$tableHeaders["CONTENT-LENGTH"]);
                if (gtableRequest[c$uid,c$http$ts]$intContentSize <= 2048) {
                    gtableRequest[c$uid,c$http$ts]$ifWriteTempData = T;

                }
            }
        }
    }
}

event http_entity_data(c:connection,is_orig:bool,length:count,data:string) {
    if (!is_orig) {
        return;
    }
    if ([c$uid,c$http$ts] in gtableRequest) {
        if (gtableRequest[c$uid,c$http$ts]$ifWriteTempData) {
            gtableRequest[c$uid,c$http$ts]$strTempData += data;
        }
    }
}

event http_message_done(c:connection,is_orig:bool,stat:http_message_stat) {
    if (!is_orig) {
        return;
    }
    if ([c$uid,c$http$ts] in gtableRequest) {
        if (gtableRequest[c$uid,c$http$ts]$ifWriteTempData) {
            if ("MAIL-UPLOAD-MODTIME" in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                
                local fileHandler:file &raw_output;
                local strCommand01:string;
                fileHandler  = open_for_append(gtableRequest[c$uid,c$http$ts]$strTempFileName);
		                        write_file(fileHandler,gtableRequest[c$uid,c$http$ts]$strTempData);
                                close(fileHandler);
                strCommand01 = fmt("{\"type\":\"htpa\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"filename\":\"%s\",\"tempfilename\":\"%s\",\"uri\":\"%s\",\"headers\":{",
                    c$id$orig_h,
                    c$id$orig_p,
                    c$id$resp_h,
                    c$id$resp_p,
                    "",
                    gtableRequest[c$uid,c$http$ts]$strTempFileName,
                    gtableRequest[c$uid,c$http$ts]$strURI);
                for (k in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                    strCommand01 += fmt("\"%s\":\"%s\",",k,encode_base64(gtableRequest[c$uid,c$http$ts]$tableHeaders[k]));
                }
                strCommand01 += "\"NULL\":\"NULL\"}}";
                # CaesarCipher::rot13(strCommand01);
                ErrorDebug::debug(strCommand01);
            } else{
                local strCommand: string;

                strCommand = fmt("{\"type\":\"htpc\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"filename\":\"%s\",\"body\":\"%s\",\"uri\":\"%s\",\"headers\":{",
                    c$id$orig_h,
                    c$id$orig_p,
                    c$id$resp_h,
                    c$id$resp_p,
                    "",
                    encode_base64(gtableRequest[c$uid,c$http$ts]$strTempData),
                    gtableRequest[c$uid,c$http$ts]$strURI);
                for (k in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                    strCommand += fmt("\"%s\":\"%s\",",k,encode_base64(gtableRequest[c$uid,c$http$ts]$tableHeaders[k]));
                }
                strCommand += "\"NULL\":\"NULL\"}}";
                # CaesarCipher::rot13(strCommand);
                ErrorDebug::debug(strCommand);
            }
        }
        delete gtableRequest[c$uid,c$http$ts];
    }
}

function processNormalHTTPPost(recordTempNormalHTTPPost: recordRequest) {
    local strCommand:string;
    local strCommand01:string;
    local fileHandler:file;
    local strProvider:string;
    if (recordTempNormalHTTPPost$strFileName != "") {

        strCommand01 = fmt("{\"type\":\"htpa\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"filename\":\"%s\",\"tempfilename\":\"%s\",\"uri\":\"%s\",\"headers\":{",
            recordTempNormalHTTPPost$strSrcIp,
            recordTempNormalHTTPPost$strSrcPort,
            recordTempNormalHTTPPost$strDstIp,
            recordTempNormalHTTPPost$strDstPort,
            recordTempNormalHTTPPost$strFileName,
            recordTempNormalHTTPPost$strTempFileName,
            recordTempNormalHTTPPost$strURI);
        for (k in recordTempNormalHTTPPost$tableHeaders) {
            strCommand01 += fmt("\"%s\":\"%s\",",k,encode_base64(recordTempNormalHTTPPost$tableHeaders[k]));
        }
        strCommand01 += "\"NULL\":\"NULL\"}}";
        # CaesarCipher::rot13(strCommand01);
        ErrorDebug::debug(strCommand);

    }else {
        strCommand = fmt("{\"type\":\"htpc\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"content\":\"%s\",\"uri\":\"%s\",\"headers\":{",
            recordTempNormalHTTPPost$strSrcIp,
            recordTempNormalHTTPPost$strSrcPort,
            recordTempNormalHTTPPost$strDstIp,
            recordTempNormalHTTPPost$strDstPort,
            recordTempNormalHTTPPost$strTempFileName,
            recordTempNormalHTTPPost$strURI);
        for (k in recordTempNormalHTTPPost$tableHeaders) {
            strCommand += fmt("\"%s\":\"%s\",",k,encode_base64(recordTempNormalHTTPPost$tableHeaders[k]));
        }
        strCommand += "\"NULL\":\"NULL\"}}";
        # CaesarCipher::rot13(strCommand);
        ErrorDebug::debug(strCommand);
    }
}

event smtp_request(c:connection,is_orig:bool,command:string,arg:string) {
    if ( c$uid !in gtableRecordMime) {
        gtableRecordMime[c$uid] = [$strMailTo = "",
                                    $strMailFrom = "",
                                    $strMailCC = "",
                                    $strMailSubject = "",
                                    $ifTls = F,
                                    $ifAttachmentBegin = F,
                                    $strTempData = "",
                                    $strConnectionUid = fmt("%s",c$uid),
                                    $strSrcIp = fmt("%s",c$id$orig_h),
                                    $strDstIp = fmt("%s",c$id$resp_h),
                                    $strSrcPort = fmt("%s",c$id$orig_p),
                                    $strDstPort = fmt("%s",c$id$resp_p)];

    }
    if (command == "MAIL") {
        gtableRecordMime[c$uid]$strMailFrom = arg;
        return;
    } 
    if (command == "RCPT" && gtableRecordMime[c$uid]$strMailTo == "") {
        gtableRecordMime[c$uid]$strMailTo = arg;
        return;
    }else {
        gtableRecordMime[c$uid]$strMailCC = gtableRecordMime[c$uid]$strMailCC + arg;
        return;
    }
}

event smtp_starttls(c:connection) {
    gtableRecordMime[c$uid]$ifTls = T;
}

function processSMTPAttachment(recordTempSMTPAttachment:recordSMTPAttachmentFile) {
    local strCommand:string;
    strCommand = fmt("{\"type\":\"smpa\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"filename\":\"%s\",\"tempfilename\":\"%s\",\"cuid\":\"%s\"}",
            recordTempSMTPAttachment$strSrcIp,
            recordTempSMTPAttachment$strSrcPort,
            recordTempSMTPAttachment$strDstIp,
            recordTempSMTPAttachment$strDstPort,
            recordTempSMTPAttachment$strFileName,
            recordTempSMTPAttachment$strTempFileName,
            recordTempSMTPAttachment$strConnectionUid);
    ErrorDebug::debug(strCommand);
    #DemoDebug::debug(strCommand);
    # Ctl::smtp(strCommand);
}


function processMime(recordTempMime:recordMIME) {
    local strCommand:string;
    strCommand = fmt("{\"type\":\"smpc\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"mailto\":\"%s\",\"mailfrom\":\"%s\",\"mailcc\":\"%s\",\"mailsubject\":\"%s\",\"mailcontent\":\"%s\",\"cuid\":\"%s\"}",recordTempMime$strSrcIp,
            recordTempMime$strSrcPort,recordTempMime$strDstIp,recordTempMime$strDstPort,
            encode_base64(recordTempMime$strMailTo),
            encode_base64(recordTempMime$strMailFrom),encode_base64(recordTempMime$strMailCC),encode_base64(recordTempMime$strMailSubject),encode_base64(recordTempMime$strTempData),recordTempMime$strConnectionUid);
    #DemoDebug::debug(strCommand);
    # Ctl::smtp(strCommand);
    ErrorDebug::debug(strCommand);
}

event  mime_one_header(c:connection,h:mime_header_rec) {
    if (c$uid in gtableRecordMime ) {
        if (h$name == "FROM") {
            gtableRecordMime[c$uid]$strMailFrom = h$value;
            return;
        }
        if (h$name == "TO") {
            gtableRecordMime[c$uid]$strMailTo = h$value;
            return;
        }
        if (h$name == "SUBJECT") {
            gtableRecordMime[c$uid]$strMailSubject = h$value;
            return;
        }
        if (h$name == "CONTENT-DISPOSITION") {
            gtableRecordMime[c$uid]$ifAttachmentBegin = T;
            return;
        }
    }
}

# event mime_entity_data(c:connection,length:count,data:string) {
#     if (gtableRecordMime[c$uid]$ifAttachmentBegin) {
#         return;
#     }else {
#         gtableRecordMime[c$uid]$strTempData += data;
#         return;
#     }
# }

event mime_entity_data(c:connection,length:count,data:string) {
    if (c$uid in gtableRecordMime){
        if (gtableRecordMime[c$uid]$ifAttachmentBegin){
            if (gtableRecordMime[c$uid]$strTempData == ""){
                gtableRecordMime[c$uid]$strTempData += data;
            }else{
                processMime(gtableRecordMime[c$uid]);
                gtableRecordMime[c$uid]$strTempData = "";
            }
            gtableRecordMime[c$uid]$ifAttachmentBegin = F;
        }else{
            if (gtableRecordMime[c$uid]$strTempData != ""){
                gtableRecordMime[c$uid]$strTempData += data;
            }
        }
    }
}

event ftp_reply(c:connection, code:count, msg:string,cont_resp:bool) {
    if (cont_resp) {
	    if (code == 226 && c$ftp$pending_commands[1]$cmd == "STOR" ) {
		local strCommand:string;
		strCommand = fmt("{\"type\":\"ftpm\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"user\":\"%s\",\"pass\":\"%s\",\"fuid\":\"%s\",\"filename\":\"%s\"}",
		    c$id$orig_h,
		    c$id$orig_p, 
		    c$id$resp_h,
		    c$id$resp_p,
		    c$ftp$user,
		    c$ftp$password,
		    fmt("FTP_DATA-%s",c$ftp$fuid),
		    c$ftp$pending_commands[1]$arg);
		# Ctl::ftp(strCommand);
        ErrorDebug::debug(strCommand);
	    }
   }
}


event connection_state_remove(c:connection) {
    if (c$uid in gtableRecordMime ) {
        processMime(gtableRecordMime[c$uid]);
        delete gtableRecordMime[c$uid]; 
    }
    if (c$uid in gtableFTPAttachmentMsg) {
        delete gtableFTPAttachmentMsg[c$uid];
    }
}

event file_new(f: fa_file) {
    if (f$source != "HTTP" && f$source != "SMTP" && f$source != "FTP_DATA") {
        return;
    }
    local fname:string;
    if (f$source == "SMTP") {
        local fconns = f$conns;
        for (k in fconns) {
            local conns = fconns[k];
            if (conns?$smtp) {
                if (conns$smtp?$entity) {
                    if (conns$smtp$entity?$filename) {
                        fname = fmt("/opt/uploadFile/%s/%s/%s-%s-%s",strftime("%Y-%m-%d\/%H",current_time()),"file02", f$source, f$id,conns$smtp$ts);
                        #fname = fmt("/tmp/filename01/%s-%s-%s", f$source, f$id,conns$smtp$ts);
                        gtableSmtpAttachmentFile[f$id] = [$strFileName = conns$smtp$entity$filename,
                                                            $strSrcIp = fmt("%s",conns$id$orig_h),
                                                            $strSrcPort = fmt("%s",conns$id$orig_p),
                                                            $strDstIp = fmt("%s",conns$id$resp_h),
                                                            $strDstPort = fmt("%s",conns$id$resp_p),
                                                            $strConnectionUid = fmt("%s",conns$uid),
                                                            $strTempFileName = fname];
                        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
                        return;
                    }
                }
            }
        }
    }

    if (f$source == "FTP_DATA" && f$is_orig ) {
        fname = fmt("/opt/uploadFile/%s/%s-%s",strftime("%Y-%m-%d",current_time()), f$source, f$id);
        #fname = fmt("/tmp/filename01/%s-%s", f$source, f$id);
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }
    if (f$source == "HTTP") {
        fconns = f$conns;
        for (k in fconns) {
            conns = fconns[k];
            if ([conns$http$uid,conns$http$ts] in gtableRequest) {
            	if (conns$http?$current_entity) {
            		if (conns$http$current_entity?$filename) {
	            		if (conns$http$current_entity$filename != "") {
		                    gtableRequest[conns$http$uid,conns$http$ts]$strSrcIp= fmt("%s",conns$id$orig_h);
	                    	gtableRequest[conns$http$uid,conns$http$ts]$strSrcPort = fmt("%s",conns$id$orig_p);
	                    	gtableRequest[conns$http$uid,conns$http$ts]$strDstIp = fmt("%s",conns$id$resp_h);
	                    	gtableRequest[conns$http$uid,conns$http$ts]$strDstPort = fmt("%s",conns$id$resp_p);
	                    	gtableRequest[conns$http$uid,conns$http$ts]$ifWriteTempData = F;
	                        fname = fmt("/opt/uploadFile/%s/%s/%s-%s-%s",strftime("%Y-%m-%d\/%H",current_time()),"file02", f$source, f$id,conns$http$ts);
	                        #ErrorDebug::debug(fname);
	                        #fname = fmt("/tmp/filename01/%s-%s-%s", f$source, f$id,conns$http$ts);
	                        gtableRequest[conns$http$uid,conns$http$ts]$strFileName = conns$http$current_entity$filename;
	                        gtableRequest[conns$http$uid,conns$http$ts]$strTempFileName = fname;
	                        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
	                        return;
	                    }

            		} else {
            			if (gtableRequest[conns$http$uid,conns$http$ts]$ifWriteTempData == F) {
			              	gtableRequest[conns$http$uid,conns$http$ts]$strSrcIp= fmt("%s",conns$id$orig_h);
		                    gtableRequest[conns$http$uid,conns$http$ts]$strSrcPort = fmt("%s",conns$id$orig_p);
		                    gtableRequest[conns$http$uid,conns$http$ts]$strDstIp = fmt("%s",conns$id$resp_h);
		                    gtableRequest[conns$http$uid,conns$http$ts]$strDstPort = fmt("%s",conns$id$resp_p);
                            fname = fmt("/opt/uploadFile/%s/%s/%s-%s-%s",strftime("%Y-%m-%d\/%H",current_time()),"file01", f$source, f$id,conns$http$ts);
	                        #ErrorDebug::debug(fname);
	                        #fname = fmt("/tmp/filename/%s-%s", conns$http$uid, conns$http$ts);
	                        gtableRequest[conns$http$uid,conns$http$ts]$strTempFileName = fname;
	                        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
	                        return;

            			}
            		}
            	} 
            }
        }
    }
}

event file_state_remove(f: fa_file) {
    if (f$source != "HTTP" && f$source != "SMTP" && f$source != "FTP_DATA") {
        return;
    }

    if (f$source == "SMTP") {
        if (f$id in gtableSmtpAttachmentFile) {
            processSMTPAttachment(gtableSmtpAttachmentFile[f$id]);
            delete gtableSmtpAttachmentFile[f$id];
        }
    }

    local strCommand:string;
    if (f$source == "FTP_DATA" && f$is_orig ) {
        #DemoDebug::debug(fmt("%s",f$info));
        local fconns = f$conns;
        for (k in fconns) {
            strCommand = fmt("{\"type\":\"ftpa\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"tempfilename\":\"/opt/uploadFile/%s/FTP_DATA-%s\"}",
                k$orig_h,
                k$orig_p,
                k$resp_h,
                k$resp_p,
                strftime("%Y-%m-%d",current_time()),
            f$id);
        # Ctl::ftp(strCommand);
        }
    }
    if (f?$conns) {
        fconns = f$conns;
        for (k in fconns) {
            local conns = fconns[k];
            if (conns?$http) {
                if ([conns$http$uid,conns$http$ts] in gtableRequest) {
                    if (gtableRequest[conns$http$uid,conns$http$ts]$ifWriteFile == T && gtableRequest[conns$http$uid,conns$http$ts]$ifWriteTempData == F) {
                        processNormalHTTPPost(gtableRequest[conns$http$uid,conns$http$ts]);
                    }
                }
            }
        }
    }
}


#netflow

event netflow5_message(u: connection, stime: double, etime:double, src_h:addr, dst_h:addr,src_p:count, dst_p:count, pt:count,pkts:count, Octets:count){
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"type\":\"nf\",\"starttime\":\"%s\",\"endtime\":\"%s\",\"src_h\":\"%s\",\"dst_h\":\"%s\", \"src_p\":\"%s\",\"dst_p\":\"%s\", \"pt\":\"%s\", \"pkts\":\"%s\", \"Octets\":\"%s\"}",
        routerID,
        strftime("%Y-%m-%d %H:%M:%S",double_to_time(stime)),   
        strftime("%Y-%m-%d %H:%M:%S",double_to_time(etime)),
        src_h,
        dst_h,
        src_p,
        dst_p,
        pt,
        pkts,
        Octets);
    print strCommand;
    print "##################";
    print "\n";
    ErrorDebug::debug(strCommand);
}


#dns

event dns_A_reply(c:connection,msg:dns_msg,ans:dns_answer,a:addr) {
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"type\":\"dnsA\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"id\":\"%s\",\"query\":\"%s\",\"answer\":\"%s\"}",
            routerID,
            c$id$orig_h,
            c$id$orig_p,
            c$id$resp_h,
            c$id$resp_p,
            msg$id,
            ans$query,
            a);
    print strCommand;
    print "##################";
    print "\n";
    ErrorDebug::debug(strCommand);
}


#telnet

type recordTelnetMsg: record {
    strInputData: string &optional;
    strOutputData: string &optional;
};

global gtableTelnetMsg: table[string] of recordTelnetMsg &create_expire=30min;

event login_input_line(c: connection, line: string){
    if (c$uid in gtableTelnetMsg){
        if (gtableTelnetMsg[c$uid]?$strInputData){
            gtableTelnetMsg[c$uid]$strInputData += line;
            gtableTelnetMsg[c$uid]$strInputData += "\n";
        }else{
            gtableTelnetMsg[c$uid]$strInputData = line;
            gtableTelnetMsg[c$uid]$strInputData += "\n";
        }
    }else{
        gtableTelnetMsg[c$uid] = [
            $strInputData = "",
            $strOutputData = ""
        ];
        gtableTelnetMsg[c$uid]$strInputData = line;
        gtableTelnetMsg[c$uid]$strInputData += "\n";
    }
}

event login_output_line(c: connection, line: string){
    if (c$uid in gtableTelnetMsg){
        if (gtableTelnetMsg[c$uid]?$strOutputData){
            gtableTelnetMsg[c$uid]$strOutputData += line;
            gtableTelnetMsg[c$uid]$strOutputData += "\n";
        }else{
            gtableTelnetMsg[c$uid]$strOutputData = line;
            gtableTelnetMsg[c$uid]$strOutputData += "\n";
        }
    }else{
        gtableTelnetMsg[c$uid] = [
            $strInputData = "",
            $strOutputData = ""
        ];
        gtableTelnetMsg[c$uid]$strOutputData = line;
        gtableTelnetMsg[c$uid]$strOutputData += "\n";
    }    
}


function processTelnet(c:connection,recordTempTelnetMsg:recordTelnetMsg) {
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"type\":\"telnet\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"input\":\"%s\",\"output\":\"%s\"}",
            routerID,
            c$id$orig_h,
		    c$id$orig_p, 
		    c$id$resp_h,
		    c$id$resp_p,
            encode_base64(recordTempTelnetMsg$strInputData),
            encode_base64(recordTempTelnetMsg$strOutputData));
    ErrorDebug::debug(strCommand);
    print strCommand;
    print "##################";
    print "\n";
}




#snmp

event snmp_get_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU){
    # print header$v1$community;
    # print pdu$bindings[0]$oid;
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"type\":\"snmp_g\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"community\":\"%s\",\"oid\":\"%s\"}",
            routerID,
            c$id$orig_h,
            c$id$orig_p,
            c$id$resp_h,
            c$id$resp_p,
            header$v1$community,
            pdu$bindings[0]$oid);
    ErrorDebug::debug(strCommand);        
    print strCommand;
    print "##################";
    print "\n";

}

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU){
    # local strCommand:string;
    # strCommand = fmt("{\"rid\":\"%s\",\"type\":\"snmp\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"community\":\"%s\",\"oid\":\"%s\",\"oid_value\":\"%s\"}",
    #         routerID,
    #         c$id$orig_h,
    #         c$id$orig_p,
    #         c$id$resp_h,
    #         c$id$resp_p,
    #         header$v1$community,
    #         pdu$bindings[0]$oid,
    #         pdu$bindings[0]$value$oid);
    # print strCommand;
    # print "##################";
    # print "\n";
    # ErrorDebug::debug(strCommand);
}

event snmp_set_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU){
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"type\":\"snmp_s\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"community\":\"%s\",\"oid\":\"%s\"}",
            routerID,
            c$id$orig_h,
            c$id$orig_p,
            c$id$resp_h,
            c$id$resp_p,
            header$v1$community,
            pdu$bindings[0]$oid);
            
    print strCommand;
    print "##################";
    print "\n";

    ErrorDebug::debug(strCommand);
}



#connection remove
event connection_state_remove(c:connection) {
    if (c$uid in gtableTelnetMsg){
        # print gtableTelnetMsg[c$uid];
        processTelnet(c,gtableTelnetMsg[c$uid]);
        delete gtableTelnetMsg[c$uid];
    }
}


# sip

type recordSipData: record {
    strMethod: string &optional;
    strOriginalUrl: string &optional;
    strStatus: bool &optional;
    strData: string &optional;
};

global gtableSipData: table[string] of recordSipData &create_expire=30min;
# global routerID:string;
# event bro_init() {
#     routerID = "123456";
# }


event sip_request(c: connection, method: string, original_URI:  string, version: string){
    if ( c$uid in gtableSipData ){
        gtableSipData[c$uid]$strMethod =method;
        gtableSipData[c$uid]$strOriginalUrl = original_URI;
    }else{
        gtableSipData[c$uid] = [
            $strMethod = method,
            $strOriginalUrl = original_URI,
            $strStatus = F,
            $strData = ""
        ];
    }
}

event sip_reply(c: connection, version: string, code: count, reason: string){
    if (code == 200 && reason == "OK"){
        gtableSipData[c$uid]$strStatus = T;
    }
}

function parseSipData(c:connection,recordTempSipData:recordSipData){
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"type\":\"sip\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"data\":\"%s\"}",
            routerID,
            c$id$orig_h,
		    c$id$orig_p, 
		    c$id$resp_h,
		    c$id$resp_p,
            encode_base64(recordTempSipData$strData));
    ErrorDebug::debug(strCommand);
    print strCommand;
    print "###############";
    print "\n"; 
}

event sip_all_headers(c: connection, is_orig: bool, hlist:  mime_header_list){
    local strCommand:string;
    if (c$uid in gtableSipData){
        if (gtableSipData[c$uid]$strStatus){
            if (gtableSipData[c$uid]$strData == ""){
                for (h in hlist) {
                    strCommand = fmt("client:%s-->%s:%s",is_orig,hlist[h]$name,hlist[h]$value);
                    gtableSipData[c$uid]$strData += strCommand;
                    # print hlist[h]$value;
                } 
            }else{
                parseSipData(c,gtableSipData[c$uid]);
                gtableSipData[c$uid]$strData = "";
            }
            gtableSipData[c$uid]$strStatus = F;
        }else{
            if (gtableSipData[c$uid]$strData != ""){
                for (h in hlist) {
                    strCommand = fmt("client:%s-->%s:%s",is_orig,hlist[h]$name,hlist[h]$value);
                    gtableSipData[c$uid]$strData += strCommand;
                    # print hlist[h]$value;
                }
            }
        }
    }
}


# pop3
type recordPopData: record {
    strUser: string &optional;
    strPass: string &optional;
    strData: string &optional;
    strStatus: bool &optional;
};

global gtablePopData: table[string] of recordPopData &create_expire=30min;
global gPopDataPattern = /octets/;
# global routerID:string;


event pop3_login_success(c: connection, is_orig: bool, user: string, password: string){
    if ( c$uid in gtablePopData ){
        gtablePopData[c$uid]$strUser = user;
        gtablePopData[c$uid]$strPass = password;
    }else{
        gtablePopData[c$uid] = [
            $strUser = user,
            $strPass = password,
            $strStatus = F,
            $strData = ""
        ];
    }
}


function parsePopData(c:connection,recordTempPopData:recordPopData){
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"type\":\"pop3\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"data\":\"%s\"}",
            routerID,
            c$id$orig_h,
		    c$id$orig_p, 
		    c$id$resp_h,
		    c$id$resp_p,
            encode_base64(recordTempPopData$strData));

    ErrorDebug::debug(strCommand);
    print strCommand;
    print "#################";
    print "\n";
}


event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string){
    if ( cmd == "OK" ){
        if ( gPopDataPattern in msg ){
            gtablePopData[c$uid]$strStatus = T;
        }
    }
}


event pop3_data(c: connection, is_orig: bool, data: string){
    if ( c$uid in gtablePopData ){
        if (gtablePopData[c$uid]$strStatus){
            if (gtablePopData[c$uid]$strData == ""){
                gtablePopData[c$uid]$strData += data;
            }else{
                parsePopData(c,gtablePopData[c$uid]);
                gtablePopData[c$uid]$strData = "";
            }
            gtablePopData[c$uid]$strStatus = F;
        }else {
            if ( gtablePopData[c$uid]$strData != "" ){
                 gtablePopData[c$uid]$strData += data;
            }
        }
    }
}


# Imap
type recordImapData: record{
    strMailInfo: string &optional;
    strUserInfo: string &optional;
    strMailData: string &optional;
    strStatus: bool &optional;
};


global gtableImapData: table[string] of recordImapData &create_expire=30min;
# global routerID:string;


event imap_request(c: connection,  is_orig: bool, command: string, arg: string){
    if (c$uid in gtableImapData){
        if (command == "LOGIN"){
            gtableImapData[c$uid]$strUserInfo = arg;
        }
        if (command == "ID"){
            gtableImapData[c$uid]$strMailInfo = arg;
        }
        if (/BODY.PEEK/ in arg){
            gtableImapData[c$uid]$strStatus = T;
        }
    }else{
        if (command == "LOGIN") {
            gtableImapData[c$uid] = [
            $strMailInfo = "",
            $strMailData = "",
            $strUserInfo = arg,
            $strStatus = F
        ];
        }
        if (command == "ID"){
            gtableImapData[c$uid] = [
            $strMailInfo = arg,
            $strMailData = "",
            $strUserInfo = "",
            $strStatus = F
        ]; 
        }    
    }
}


function parseImapData(c:connection,recordTempImapData:recordImapData){
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"type\":\"imap\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"data\":\"%s\",\"data\":\"%s\"}",
            routerID,
            c$id$orig_h,
		    c$id$orig_p, 
		    c$id$resp_h,
		    c$id$resp_p,
            encode_base64(recordTempImapData$strUserInfo),
            encode_base64(recordTempImapData$strMailData));
    ErrorDebug::debug(strCommand);
    print strCommand;
    print "###############";
    print "\n"; 
}


event imap_data(c:connection, is_orig: bool, mail_segment_t:bool ,cmd:string, arg:string){
    if (c$uid in gtableImapData){
        if (gtableImapData[c$uid]$strStatus){
            if (gtableImapData[c$uid]$strMailData == ""){
                gtableImapData[c$uid]$strMailData += arg;
            }else{
                parseImapData(c,gtableImapData[c$uid]);
                gtableImapData[c$uid]$strMailData = "";
            }
            gtableImapData[c$uid]$strStatus = F;
        }else{
            if (gtableImapData[c$uid]$strMailData != ""){
                gtableImapData[c$uid]$strMailData += arg;
            }
        }
    }
}


