#J'importe toutes les bibliothèques dont j'aurai besoin
import logging

import dearpygui.dearpygui as dpg

from chat_client import ChatClient
from generic_callback import GenericCallback
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
import os
import logging
import serpent
from basic_gui import *

#
salt=b'hello'
#Initialisation de la fonction de dérivation de clé
kdf=PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16, #taille de la clef
    salt=salt, # donnée qui hache le mot de passe
    iterations=180000
)

class CipheredGUI(BasicGUI): # Definition de la classe CipheredGui qui hérite de la classe BasicGui

    def __init__(self)->None:
        # constructor
        super().__init__()
        self._key= None # Initialiser ce champ avec une valeur par defaut qui contiendra la clef de chiffrement
        
    def _create_connection_window(self)->None:
        # windows about connexion
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            
            for field in ["host", "port", "name"]:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")
                    #Creation du champ password
            with dpg.group(horizontal=True): # le positionner vers l'horizontal
                dpg.add_text("password") # Ajout de texte password
                dpg.add_input_text(default_value = "", tag="connection_password",password=True) # Ajout de l'input password 

            dpg.add_button(label="Connect", callback=self.run_chat)
                
  

    def run_chat(self, sender, app_data)->None:
        # callback used by the connection windows to start a chat session
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password") #récupération du password
        self._key=kdf.derive(bytes(password, "utf-8")) # dérivation de la clef de chiffrement
        self._log.info(f"Connecting {name}@{host}@{password}:{port}")

        self._callback = GenericCallback()

        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")

    def encrypt(self,mess): #fonction encrypt qui prend en parametre une valeur string
        iv=os.urandom(16) #(nombre aléatoire) Vecteur d'initialisation qui peut etre utiliseé avec une clef secrète pour le chiffrement des données afin de déjouer les cyberattaques
        
        cipher= Cipher(algorithms.AES(self._key),modes.CTR(iv))
        encryptor=cipher.encryptor()
        remess=encryptor.update(bytes(mess,"utf-8"))
        return(remess,iv) # Retourne un tuple de bytes

    def decrypt(self,remess,iv): #fonction decrypt qui prend en paramètre un tuple
        
        cipher= Cipher(algorithms.AES(self._key),modes.CTR(iv))
        decryptor=cipher.decryptor()
        return str(decryptor.update(remess,"utf-8"))
        
        #return str(decryptor.update(remess, "utf-8")) #Retourne une valeur string utf-8
   
    
    def recv(self,iv)->None:
        # function called to get incoming messages and display them
        if self._callback is not None:
            for user, message in self._callback.get():
                
                texte=((serpent.tobytes(message[0]),serpent.tobytes(message[1])))# Fais appel à ma fonction decrypt pour dechffrer le message sérialise transformé en bytes
                donnee=self.decrypt(texte)
                self.update_text_screen(f"{user} : {donnee}") #fais appel à la fonction  update_text_screen pour faire la mise à jour tu texte sur l'écran et l'afficher (foo : bonjour)
            self._callback.clear()
    
  
    def send(self,texte)->None:
        # function called to send a message to all (broadcasting)
         
         mess=self.encrypt(texte) #Faire appel à ma fonction encrypt pour chiffrer le texte
         self._client.send_message(mess) #J'envoie ce texte chiffré à un client x 
         
    def loop(self,iv):
        # main loop
        while dpg.is_dearpygui_running():
            self.recv()
            dpg.render_dearpygui_frame()

        dpg.destroy_context()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = CipheredGUI()
    client.create()
    client.loop()

               
