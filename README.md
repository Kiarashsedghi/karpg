# karpg

KARPG is a cli arp packet generator .



## commands
There are some functions you can issue in this program to create your arp message :
  
  ### create an ARP message :
        YOUR_ARP_MESSAGE_NAMe = ( arp_fields* )
    
           arp_fields is : ( opcode = value | hlen = value | plen= vlaue | htype = value | ptype = value | sip = vlaue | tip = vlaue | smac = vlaue | tmac = value )
    
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
      default_fiels 
            >>  mess1=()
            
      change some values: 
            >>   mess1=(sip=192.168.10.1 , htype=2 , opcode=2)
        
        
  ### checking message contents :
      
      Another useful command is ( show MESSAGE_NAME ) which prints out fields of that message
     
     
     
     
     
        
        
        
     
  ### see which interface was set:
     you can check the current selected interface in program by ( show int or show interface ).
    
     by default no interface is selected
          
          
          
            
   ### setting interface :
     Another useful command is (setint) , which sets an interface for you.
         ex:
              >> setint vmnet1
            
            
   

            

    
            
