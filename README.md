# Finding-outliers

This is primarily a project used to find outliers in hosts to potentially target for further collection of info. 
The concept is to allow network teams to feed you tippers and use host collection data to feed into this project




      Overall Concepts are below 
      """
       [IOC_Hash_Compare.py]         SHA1 Comparison from all collected against offline malware db
       [Pending]                     SHA1 reverse file look up against matches against  offline malware db 
       [IOC_Hash_Compare.py]         SHA1 Comparison from all collected against NSRL
       [Pending]                     SHA1 reverse file lookup for non-Matches with executable filetypes against NSRL
       [Pending]                     SHA1 reverse lookup remainder least frequency occurence against network
      """
      """
       [registry_persistence.py]     Reg key autoruns
       [registry_persistence.py]     Reg Key software installed
       [registry_persistence.py]     Reg Key services
       [Pending]                     Reg Key all above least frequency occurence
      """
      """
       [IOC_Extraction.py]           IOC Extraction (sha1, domains, urls, emails, ipv4)
       [IOC_Hash_Compare.py]         IOC comparison against open source intelligence (scraped from websites used as pointers)
      """
      """
      [groupmembership.py]           Maps users, groups to their perspective groups and sends to an elasticsearch instance. 
      """
      """
       Processes (command Line args, proper path, proper parent, proper count)
         Loaded DLLs LFO
         Loaded DLLs - Side Loading
         Services LFO
         Services - Name, start type, connection info
         Network Connections LFO
         Network connections - correlation against Network Traffic
         Network connections - build Ports Protocols, services per host
       Prefetch LFO count of use against network - # still need more analytics for this
      """
    """
     # Need to implement - All windows Event Logs
     # Need to implement - Share info
     # Need to implement - System_Log
     # Need to implement - User Info log
     # Need to implement - File path
     # Need to implement - IOC LFO for all types against network for outliers < 5% of network
     # Need to implement - Identification of all files provided output to csv 
    """
