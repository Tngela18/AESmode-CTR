1) c'est une topologie symétrique
2) je remarque que les messages que les deux interlocuteurs s'envoient sont visibles.
3) C'est problématique puisque tous le monde pourra avoir accès à ce qui se disent et ca viole le principe de confidentialité.
4) La methode la plus simple pour pallier à ce problème est de faire un chiffrement de données car il assure la confidentialité.

       CHIFFREMENT
1)
2)Utiliser les primitives cyptographiques peuvent etre dangereuses car elles sont assez limitées. 
3) Malgré le chiffrement, un serveur malveillant peut nous nuire car le message peut etre intercepté par ce dernier à cause du manque d'authenticité. 
4) Il manque la proprieté de l'authenticité

    AUTHENTICATED SYMETRIC ENCRYPTION
1) Fernet est moins risqué car il permet un dechiffrement avec la clé donc presque impossible pour un serveur malveillant d'intercepter le message
2) cette attaque est le DDOS (DDistributed Denial Of Service)
3) la methode que l'on peut mettre en oeuvre pour eviter celà est d'allouer un certain temps au message pour que ce dernier ne soit pas réutilisable

