LastPassCrack
===============

This can be used as a tool for cracking the Lastpass Firefox add-on cache. Realistically, it can be useful  when you don't remember the password exactly but have a good idea of what it may be. It's a fork of [lastpass-sharp] (https://github.com/detunized/lastpass-sharp) with added basic command line interface and local cache decryption. 

It uses [Generex] (https://github.com/mifmif/Generex) to generate combination based on a regex string. Because of that, it requires Java JDK to be installed and JAVA_HOME environment variable pointing to it.

Execute LastpassCrack.exe from command line, specifying the following arguments:

--username - Lastpass username
--password - regex string specifying the combinations to try out. For example, [a-z]{6} would go through  all 6-letter lower case combinations. 
--slps - the path to the slps file found in AppData/local_low/LastPass directory
--sxml - the path to the sxml file in the above directory

Running this command will attempt to try all combinations and return the decrypted data to the standard output:

LastPassCrack.exe --username user@email.com --password "\$ecret[0-9]{3}" --slps C:\Users\Username\AppData\LocalLow\LastPass\xxx_lpall.slps --sxml C:\Users\P\AppData\LocalLow\LastPass\xxx_lps.act.sxml > decrypted.csv

The files stored by the LastPass Firefox add-on are protected using the Data Protection API on Windows. They can be only unprotected on the same machine on which they were protected. You can run LastpassCrack --unprotect <path> to do that, for example:

LastPassCrack.exe --unprotect C:\Users\Username\AppData\LocalLow\LastPass\xxx_lpall.slps > unprotected.slps
