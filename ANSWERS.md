1) C'est une topologie symétrique
2) Je remarque que les messages que les deux interlocuteurs s'envoient sont visibles.
3) C'est problématique puisque tous le monde pourra avoir accès à ce qui se disent et ca viole le principe de confidentialité.
4) La methode la plus simple pour pallier à ce problème est de faire un chiffrement de données car il assure la confidentialité.

       CHIFFREMENT
1)Urandom est un bon choix pour la cryptographie 
2)Utiliser les primitives cyptographiques peuvent etre dangereuses car elles sont assez limitées. 
3) Malgré le chiffrement, un serveur malveillant peut nous nuire car le message peut etre intercepté par ce dernier à cause du manque d'authenticité. 
4) Il manque la proprieté de l'authenticité.

    AUTHENTICATED SYMETRIC ENCRYPTION
1) Fernet est moins risqué car il offre à la fois la confidentialité et l'authenticité.
2) Cette attaque est le rejeu d'attaque.
3) La methode que l'on peut mettre en oeuvre pour eviter celà est d'allouer un certain temps au message pour que ce dernier ne soit pas réutilisable.

    TTL
1) Oui, je remarque que le message a une durée de vie de 30s.
2)Lorsqu'on soustrait 45 au temps d'emission (45-30=-15), le message sera considéré comme expiré et on ne pourra pas le dechiffer.
3) Non, ce n'est pas efficace pour se proteger de l'attaque précedente.
4)Si le délai soustrait au temps lors de l'émission est négatif, cela peut rendre le message inutilisable et le temps d'attente.
