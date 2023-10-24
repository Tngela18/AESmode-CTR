from fernet_gui import *
import time




class TimeFernetGUI(FernetGUI):
    def __init__(self):
        super().__init__()


    def encrypt(self, message):
        
        # Initialize the Fernet cipher with the derived key
        fernet_cipher = Fernet(self._key)
        
        
        # Encrypt the message and return it as bytes
        encrypted_message = fernet_cipher.encrypt(message.encode('utf-8'))
        #encrypted_message = fernet_cipher.encrypt(bytes(message,'utf-8'))
        return (encrypted_message, 0)

    def decrypt(self, encrypted_message):

        # Initialize the Fernet cipher with the derived key
        fernet_cipher = Fernet(self._key)
        
        # Decrypt the message and return it as a UTF-8 string
        decrypted_message = fernet_cipher.decrypt(encrypted_message[0])
        return str(decrypted_message.decode('utf-8'))
        #return (decrypted_message,'utf-8')




if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
   
    # Instantiate the class, create context, and related stuff, run the main loop
    
    client = TimeFernetGUI()
    
    
    client.create()
    client.loop()
    

