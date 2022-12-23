import gc, os, time, subprocess, pyshark, json, logging


#Change path_to_watch to pcap file location
#Watches This Directory
path_to_watch = '/pcap-for-wifi-file/'   
#Dir listing to see whats in there
before = dict ([(f, None) for f in os.listdir (path_to_watch)])
#Creates a log file for any errors that may come
logging.basicConfig(filename='/Wifi-Data/Error-Log/error.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger=logging.getLogger(__name__)
#start of loop to identify what has happened to dir after 70 secs
while 1: 
    time.sleep(5)
    #Dir listing after 5 secs to identify changes
    after = dict ([(f, None) for f in os.listdir (path_to_watch)])
    #Compares the after variable with the before variable if a change then something was added
    added = [f for f in after if not f in before] 
    #If something was added
    timestr = str(time.strftime("%Y-%m-%d_%H:%M:%S"))
    #print(timestr)
    if added:
        #loop for each pcap added to directory
        start_time = time.time()
        print(str(added) + 'added start time for pcap')
        for i in added:
            print(i)                
            f1 = '/pcap-for-wifi-file/' + i
            #Opens pcap file and filters on wifi traffic
            packets = pyshark.FileCapture(f1, display_filter='wlan')
            
            packet_list = (packets)
            packet_iter = iter(packet_list)
            
            #For loop for each packet in pcap file
            count = 0
            print('time for added pcap into loop', time.time() - start_time)
            #for packet in packets:
            for s in packet_iter:
                #print(s)
                #count += 1
                #print(count)
                try:
                    #Next packet in pcap file
                    #pcap = next(packet_iter)
                    pcap = packets.next()
                    #Gather Wifi msg in packet
                    WlanSubType= pcap.wlan.fc_type_subtype
                    WlanType = pcap.wlan.fc_type
                    #print(WlanSubType)
                    #Management Frames
                    for wtype in WlanType:
                        #count += 1
                        #print(count)
                        #print('wtype time', time.time() - start_time)
                        for wlansub in WlanSubType:
                            #print(wtype)
                            #print(wlansub)
                            if wtype == '0':
                                #print(wtype)
                                wlan_json = {'WlanType': WlanType,'WlanSubType':WlanSubType, 'BSSID': pcap.wlan.bssid, 'Transmit Address': pcap.wlan.ta, 'Reciever Address': pcap.wlan.ra, 'Channel Frequency': pcap.radiotap.channel_freq,'Antenna Signal': pcap.radiotap.dbm_antsignal, 'Is it 2ghz?': pcap.radiotap.channel_flags_2ghz, 'Is it 5ghz': pcap.radiotap.channel_flags_5ghz }  
                                #print(wlan_json)
                                #wlan_json = {'WlanType': WlanType,'WlanSubType':wlansub, 'BSSID': wlanBssid, 'ta': wlanta, 'sa': wlansa, 'cf': wlancf}
                                save = open('/Wifi-Data/Logs/management.log', '+a', errors='ignore')
                                #print(pcap.wlan.bssid)
                            elif wtype == '1':
                                #print(wtype)
                                wlan_json = {'WlanType': WlanType,'WlanSubType': WlanSubType, 'Reciever Address': pcap.wlan.ra, 'Channel Frequency': pcap.radiotap.channel_freq,'Antenna Signal': pcap.radiotap.dbm_antsignal,'Is it 2ghz?': pcap.radiotap.channel_flags_2ghz ,'Is it 5ghz?': pcap.radiotap.channel_flags_5ghz}
                                save = open('/Wifi-Data/Logs/control.log', '+a', errors='ignore')
                            elif wtype == '2':
                                #print(wtype)  
                                wlan_json = {'WlanType':WlanType,'WlanSubType': WlanSubType, 'BSSID': pcap.wlan.bssid, 'Transmit Address': pcap.wlan.ta, 'Reciever Address': pcap.wlan.ra,'Source Address': pcap.wlan.sa, 'Destination Address': pcap.wlan.da ,'Channel Frequency': pcap.radiotap.channel_freq,'Antenna Signal': pcap.radiotap.dbm_antsignal, 'Is it 2ghz?': pcap.radiotap.channel_flags_2ghz, 'Is it 5ghz?': pcap.radiotap.channel_flags_5ghz }
                                #print(wlan_json)
                                save = open('/Wifi-Data/Logs/data.log', '+a', errors='ignore')
                                #print(wlan_json)
                            else:
                                save = open('/Wifi-Data/Error-Log/UnkownMsg.log', '+a', errors="ignore")
                                save.write(WlanType)
                                save.write(WlanSubType)
                                save.close
                            #Starts determining what message it is and places it in respective json format    
                            json_clean = (json.dumps(wlan_json, indent=4, sort_keys=False))
                            #print(count)
                            #print(json_clean)
                            save.write(json_clean)
                            save.close
                            #print('saved time', time.time() - start_time)
                            #count += 1
                            #print(count)
                    #gc.collect()      
                #If error output it to the .log
                except Exception as e:
                    logging.error(e)
            #count += 1
            #print(count)
            #gc.collect()
        #Takes what was added and places it in before variable(resets the after variable to NULL)
        before = after
        #print("done")
        timestr = str(time.strftime("%Y-%m-%d_%H:%M:%S"))
        #print(timestr)
        gc.collect()
        print('complete time for pcap', time.time(), start_time

        )

