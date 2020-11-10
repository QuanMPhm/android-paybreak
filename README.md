fileencryptor is an Android App which encrypts files using AES/GCM encryption provided by the Java Cryptography Extension. 

encryptorhook is an Xposed module made to trigger when the javax.crypto.Cipher init method is called. encryptorhook extracts key material nesseacry for decryption, and broadcasts it as UDP packets

pcap is a Java program built by Maven which can filter network traffic data, retrieve UDP packets from encryptorhook, and store the key material infromation.



