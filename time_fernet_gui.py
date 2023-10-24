from fernet_gui import *
import time




class TimeFernetGUI(FernetGUI):
    def __init__(self):
        super().__init__()


    def encrypt_at_time(self, message, key, ttl=30):
        current_time = int(time.time())
        fernet_cipher = Fernet(key)
        encrypted_message = fernet_cipher.encrypt(message.encode('utf-8'))
        return f"{current_time + ttl}:{encrypted_message.decode('utf-8')}"

    def decrypt_at_time(self, token, key):
        parts = token.split(":")
        if len(parts) != 2:
            raise InvalidToken("Invalid token format")
        expiration_time = int(parts[0])
        current_time = int(time.time())
        if current_time > expiration_time:
            raise InvalidToken("Token has expired")
        fernet_cipher = Fernet(key)
        decrypted_message = fernet_cipher.decrypt(parts[1].encode('utf-8')).decode('utf-8')
        return decrypted_message

    def encrypt(self, mess):
        try:
            encrypted_message = self.encrypt_at_time(mess, self._key, ttl=30)
            return encrypted_message
        except InvalidToken as e:
            # Log the error
            print(f"Encryption Error: {str(e)}")

    def decrypt(self, mess):
        try:
            decrypted_message = self.decrypt_at_time(mess, self._key)
            return decrypted_message
        except InvalidToken as e:
            # Log the error
            print(f"Decryption Error: {str(e)}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
   
    # Instantiate the class, create context, and related stuff, run the main loop
    
    client = TimeFernetGUI()
    
    
    client.create()
    client.loop()
    

