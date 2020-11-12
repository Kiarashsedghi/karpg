# karpg

KARPG is a cli ARP packet generator.<br/>
KARPG uses self designed command line parser , usgin strong regex and some string processing functions.<br/><br/>
This project is under development.



## commands
There are some functions you can issue in this program to create & maintain your arp message :
  
  ### create an ARP message :
        YOUR_ARP_MESSAGE_NAMe = ( arp_fields* )
    
           arp_fields is : (  opcode = value | hlen = value | plen= vlaue | 
                              htype = value | ptype = value | sip = vlaue | tip = vlaue |
                              smac = vlaue | tmac = value )
    
  if you do not specify any arp_fields in paranthesis , some default values are given to above fields in ARP message :
      opcode = 1 
      hlen = 6
      plen= 4
      htype = 1  (Ethernet)
      ptype = 0x0800 (IPv4) 
      sip = 0.0.0.0
      tip = 255.255.255.255
      smac = 00:00:00:00:00:00
      tmac = ff:ff:ff:ff:ff:ff
      
   
   but these values can be changed easily by issueing create function again on that message name :
   
    ex: 
      create a message with name (mess1) and with default fields
            >>  mess1=()
            
      change some values: 
            >>   mess1=(sip=192.168.10.1 , htype=2 , opcode=2)
            
   or you can simple create a message with your initial fiels:
        
        ex
            create a new message with name ( mess2 ) and with my default fields   
                 >> mess2=(opcode= 2 , sip =192.168.10.1 , tmac= 01005e010000)
          
  ### checking message contents :
      
      Another useful command is ( show MESSAGE_NAME ) which prints out fields of that message
      
      ex 
         >> show mess2
         OUTPUT: 
          (opcode: 2 , heln: 6 , plen: 4, htype: 1,
          ptype: 2048, smac: 000000000000, tmac: 01:00:53:01:00:00, sip: 192.168.10.1 , tip:255.255.255.255)
          
     
     
  ### see which interface was set:
     you can check the current selected interface in program by ( show int or show interface ).
    
     by default no interface is selected
     
     ex 
        >> show int
        OUTPUT:
          Interface = Not set
          
          
        >> show int
        OUTPUT:
          Interface = vmnet1
          
  ### send an ARP message
       This function is for sending . This version of KARPG does not support parser for send , 
       so it simply asks you interactively for some informations.
       
       defaults:
        smac: mac address of selected NIC
        tmac: ff:ff:ff:ff:ff:ff
        count: 1
       
       ex
          >> send
              message: mess1
              smac :[d for default] d
              tmac :[d for default] d
              count :[d for default] 12


          
          
          
            
   ### setting interface :
     Another useful command is (setint) , which sets an interface for you.
         ex:
              >> setint vmnet1
              OUTPUT:
                interface {vmnet1} was set as default interface



            
   

            

    
            
