import re
import hashlib
import bcrypt
import itertools
import string

def est_email_valide(email):
    pattern_email = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern_email, email)

def est_pwd_valide(pwd):
    pattern_pwd = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return re.match(pattern_pwd, pwd)

def enregistrer_info(email, pwd):
    with open('Enregistrement.txt', 'a', newline='') as fichier:
        fichier.write(f'Email: {email}, Mot de passe: {pwd}\n')
    print('Enregistrement réussi.')

def authentifier_utilisateur(email, pwd):
    with open('Enregistrement.txt', 'r', newline='') as fichier:
        lignes = fichier.readlines()
        for ligne in lignes:
            if f'Email: {email}, Mot de passe: {pwd}' in ligne:
                return True
        return False

def bruteforce_attack(password):
    chars = string.printable.strip()
    attempts = 0
    for length in range(1, len(password) + 1):
        for guess in itertools.product(chars, repeat=length):
            attempts += 1
            guess = ''.join(guess)
            if guess == password:
                return (attempts, guess)
    return (attempts, None)

def afficher_menu():
    print("Menu:")
    print("a- Haché le mot par sha256")
    print("b- Haché le mot en (bcrypt)")
    print("c- Attaquer par dictionnaire ")
    print("q- Quitter")


def hacher_sha256(mot_de_passe):
    return hashlib.sha256(mot_de_passe.encode()).hexdigest()


def hacher_bcrypt(mot_de_passe):
    salt = bcrypt.gensalt()
    hashed_pwd = bcrypt.hashpw(mot_de_passe.encode(), salt)
    return hashed_pwd.decode()


print("Bienvenue dans le programme de amine.")
choix_authentification = input('Voulez-vous vous connecter (c) ou vous inscrire (i) ? ')

if choix_authentification == 'i':
    email = input('Entrez votre email : ')
    while not est_email_valide(email):
        print('Email invalide. Veuillez réessayer.')
        email = input('Entrez votre email : ')

    pwd = input('Entrez votre mot de passe : ')
    while not est_pwd_valide(pwd):
        print('Mot de passe invalide. Veuillez réessayer.')
        pwd = input('Entrez votre mot de passe : ')

    enregistrer_info(email, pwd)
    print('Inscription réussie.')


while True:
    afficher_menu()

    choix_menu = input('Choisissez une option du menu : ')

    if choix_menu == 'a':
        mot_a_hasher = input('Entrez le mot à hacher : ')
        resultat_hash = hacher_sha256(mot_a_hasher)
        print(f'Mot haché par sha256 : {resultat_hash}')
    elif choix_menu == 'b':
        mot_a_hasher = input('Entrez le mot à hacher  : ')
        resultat_hash = hacher_bcrypt(mot_a_hasher)
        print(f'Mot haché par bcrypt : {resultat_hash}')
    elif choix_menu == 'c':
        mot_a_attaquer = input('Entrez le mot à attaquer par dictionnaire : ')
        attempts, guess = bruteforce_attack(mot_a_attaquer)
        if guess:
            print(f"Password cracked in {attempts} attempts. The password is {guess}.")
        else:
            print(f"Password not cracked after {attempts} attempts.")
    elif choix_menu == 'q':
        print('the end of programme')
        break
    else:
        print('Option invalide. do it again .')