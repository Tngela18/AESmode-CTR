import base64
import hashlib
import logging
import serpent
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from ciphered_gui import *





class FernetGUI(CipheredGUI):
    def __init__(self):
        super().__init__()
       
      #def run_chat(self, sender, app_data,password):
        
    def run_chat(self, sender, app_data):  
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password") #récupération du password
        
        # Convert the password to bytes (UTF-8 encoding is used here)
        
        password_bytes =(bytes(password, "utf-8"))
    

        # Use SHA-256 hash function to create a 256-bit key
        #sha256 = hashlib.sha256()
        digest=hashes.Hash(hashes.SHA256())
        #sha256.update(password_bytes)
        digest.update(password_bytes)
        #self._key = sha256.digest()
        #self._key = base64.urlsafe_b64encode(sha256.digest())
        #self._key = base64.b64encode(sha256.digest())
        self._key = base64.b64encode(digest.finalize())


        self._log.info(f"Connecting {name}@{host}:{port}")

        self._callback = GenericCallback()

        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")

    def encrypt(self, mess):
        
        # Initialize the Fernet cipher with the derived key
        fernet_cipher = Fernet(self._key)
        
        
        # Encrypt the message and return it as bytes
        encrypted_message = fernet_cipher.encrypt(mess.encode('utf-8'))
        #encrypted_message = fernet_cipher.encrypt(bytes(message,'utf-8'))
        return (encrypted_message, 0)

    def decrypt(self, mess):
        encrypted_message=base64.b64encode(mess, "utf-8")

        # Initialize the Fernet cipher with the derived key
        fernet_cipher = Fernet(self._key)
        
        # Decrypt the message and return it as a UTF-8 string
        decrypted_message = fernet_cipher.decrypt(encrypted_message).decode('utf-8')
        #return str(decrypted_message.decode('utf-8'))
        return str(decrypted_message)
        
    
        
        

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
   
    # Instantiate the class, create context, and related stuff, run the main loop
    
    client = FernetGUI()
    
    
    client.create()
    client.loop()
    

