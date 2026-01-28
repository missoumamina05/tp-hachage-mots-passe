# tp-hachage-mots-passe
TP #1 - Hachage de mots de passe
# Travail Pratique #1 - Sécurité Informatique INF36207

## Hachage de Mots de Passe et Attaques par Force Brute

**Cours:** INF36207 - Sécurité Informatique  
**Session:** Hiver 2026  
**Équipe:** 23  
**Date limite:** 23 février 2026 à 19h00  
**Pondération:** 15%

---

## 📋 Description du Projet

Ce travail pratique vise à démontrer les enjeux de sécurité liés au stockage des mots de passe. Le projet comporte trois parties:

1. **Générateur de Dictionnaire** - Crée des dictionnaires de mots de passe pour attaques par force brute
2. **Vérificateur de Hachage bcrypt** - Teste les hachages bcrypt pour trouver les mots de passe
3. **Résolution de Hachages** - Applique les deux premières parties pour solutionner des hachages réels

---

## 🎯 Objectifs Pédagogiques

À la fin de ce TP, vous serez capables de:

- ✅ Comprendre le fonctionnement réel du hachage de mots de passe
- ✅ Distinguer les méthodes faibles des méthodes sécuritaires
- ✅ Mesurer concrètement l'impact des choix techniques
- ✅ Recommander une politique de mots de passe réaliste
- ✅ Expliquer les enjeux de sécurité à des non-spécialistes

---

## 📦 Structure du Projet

```
tp-hachage-mots-passe/
├── README.md                          # Ce fichier
├── generateur_dictionnaire.py         # Partie #1 - Générateur
├── verificateur_hachage.py            # Partie #2 - Vérificateur (à venir)
├── .gitignore                         # Fichiers à ignorer
├── dico_fr.txt                        # Dictionnaire français fourni
├── dictionnaires/                     # Dictionnaires générés
│   ├── dico_1.txt
│   ├── dico_2.txt
│   └── ...
└── rapport/                           # Rapport final
    └── rapport_tp.pdf
```

---

## 🚀 Installation et Utilisation

### Prérequis

- **Python 3.8+** (testé sur Python 3.10 et 3.11)
- **Système:** Windows 11 (recommandé), macOS, Linux
- **Modules requis:** 
  - `tkinter` (inclus avec Python)
  - `bcrypt` (pour la partie #2)

### Installation

1. **Cloner le repository:**
   ```bash
   git clone https://github.com/ton-username/tp-hachage-mots-passe.git
   cd tp-hachage-mots-passe
   ```

2. **Installer les dépendances (optionnel):**
   ```bash
   pip install bcrypt
   ```

### Lancer l'application Partie #1 (Générateur)

```bash
python generateur_dictionnaire.py
```

**Interface:**
- Sélectionner la longueur minimale et maximale des mots
- Choisir les types de caractères (minuscules, majuscules, chiffres, spéciaux)
- Cliquer sur "Calculer l'estimation" pour voir la taille estimée
- Sélectionner le fichier de sortie
- Cliquer sur "Générer le dictionnaire"

**Exemple:**
- Longueur min: 1
- Longueur max: 3
- Caractères: a-z + 0-9
- Fichier: `dico_exemple.txt`

### Lancer l'application Partie #2 (Vérificateur)

```bash
python verificateur_hachage.py
```

**Interface:**
- Fournir un hachage bcrypt (format: `$2b$10$...`)
- Sélectionner le fichier dictionnaire généré (Partie #1)
- L'application teste chaque mot du dictionnaire
- Affiche le mot de passe quand trouvé

---

## 🔧 Détails Techniques

### Partie #1 - Générateur de Dictionnaire

**Langage:** Python 3.10+  
**Framework GUI:** Tkinter (natif)  
**Algorithme:** `itertools.product()` pour générer les combinaisons

**Caractéristiques:**
- Interface graphique intuitive
- Estimation en temps réel
- Barre de progression avec temps écoulé
- Support Threading pour interface responsive
- Gestion d'arrêt gracieux

**Exemple de sortie:**
```
a
b
c
...
aa
ab
ac
...
```

### Partie #2 - Vérificateur Hachage bcrypt

**Langage:** Python 3.10+  
**Bibliothèque:** `bcrypt` (USENIX bcrypt implementation)  
**Facteur de coût:** 10 (standard)

**Processus:**
1. Charger le dictionnaire
2. Pour chaque mot:
   - Générer hachage bcrypt(10) du mot
   - Comparer avec hachage cible
   - Si correspondance → afficher résultat
3. Afficher temps total et nombre de tentatives

---

## 💻 Code Source - Partie #1 (Générateur)

### `generateur_dictionnaire.py`

```python
"""
================================================================================
GÉNÉRATEUR DE DICTIONNAIRE DE MOTS DE PASSE
Travail Pratique - Sécurité Informatique INF36207
================================================================================
Application de génération de dictionnaires pour attaques par force brute.
Permet de générer toutes les combinaisons possibles selon les paramètres donnés.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import itertools
from threading import Thread
from datetime import datetime
import time


class GenerateurDictionnaire:
    """
    Classe principale pour la génération de dictionnaires de mots de passe.
    
    Interface graphique permettant à l'utilisateur de:
    - Définir les longueurs min/max des mots
    - Choisir les caractères à utiliser
    - Estimer la taille du dictionnaire
    - Générer et sauvegarder le dictionnaire dans un fichier
    """
    
    def __init__(self, root):
        """Initialise la fenêtre principale et les variables"""
        self.root = root
        self.root.title("Générateur de Dictionnaire de Mots de Passe")
        self.root.geometry("700x800")
        self.root.resizable(False, False)
        
        # Variables pour stocker les valeurs saisies
        self.min_length = tk.IntVar(value=1)
        self.max_length = tk.IntVar(value=3)
        self.output_file = tk.StringVar()
        self.caracteres = tk.StringVar()
        
        # Checkboxes pour les types de caractères
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_uppercase = tk.BooleanVar(value=False)
        self.use_digits = tk.BooleanVar(value=False)
        self.use_special = tk.BooleanVar(value=False)
        self.special_chars = tk.StringVar(value="#$%?&*")
        
        # Flags pour contrôler la génération
        self.creation_en_cours = False
        self.thread_generation = None
        
        # Construire l'interface
        self.build_ui()
    
    def build_ui(self):
        """Construit l'interface graphique de l'application"""
        
        # Frame principal avec padding
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # ===== SECTION 1: LONGUEURS DES MOTS =====
        ttk.Label(main_frame, text="LONGUEURS DES MOTS", 
                 font=("Arial", 13, "bold")).grid(row=0, column=0, columnspan=2, 
                                                   sticky=tk.W, pady=(10, 15))
        
        ttk.Label(main_frame, text="Longueur minimale:").grid(row=1, column=0, 
                                                               sticky=tk.W, pady=5)
        ttk.Spinbox(main_frame, from_=1, to=20, textvariable=self.min_length, 
                   width=10).grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(main_frame, text="Longueur maximale:").grid(row=2, column=0, 
                                                               sticky=tk.W, pady=5)
        ttk.Spinbox(main_frame, from_=1, to=20, textvariable=self.max_length, 
                   width=10).grid(row=2, column=1, sticky=tk.W)
        
        # ===== SECTION 2: CARACTÈRES PERMIS =====
        ttk.Label(main_frame, text="CARACTÈRES PERMIS", 
                 font=("Arial", 13, "bold")).grid(row=3, column=0, columnspan=2, 
                                                   sticky=tk.W, pady=(20, 15))
        
        ttk.Checkbutton(main_frame, text="Alphabet minuscule (a-z)", 
                       variable=self.use_lowercase).grid(row=4, column=0, 
                                                          columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Checkbutton(main_frame, text="Alphabet majuscule (A-Z)", 
                       variable=self.use_uppercase).grid(row=5, column=0, 
                                                          columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Checkbutton(main_frame, text="Chiffres (0-9)", 
                       variable=self.use_digits).grid(row=6, column=0, 
                                                      columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Checkbutton(main_frame, text="Caractères spéciaux", 
                       variable=self.use_special).grid(row=7, column=0, 
                                                       columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Label(main_frame, text="Caractères spéciaux (personnalisés):").grid(
            row=8, column=0, sticky=tk.W, pady=(10, 5))
        ttk.Entry(main_frame, textvariable=self.special_chars, 
                 width=40).grid(row=8, column=1, sticky=tk.EW)
        
        # ===== SECTION 3: ESTIMATION =====
        ttk.Label(main_frame, text="ESTIMATION", 
                 font=("Arial", 13, "bold")).grid(row=9, column=0, columnspan=2, 
                                                   sticky=tk.W, pady=(20, 15))
        
        ttk.Button(main_frame, text="Calculer l'estimation", 
                  command=self.calculer_estimation).grid(row=9, column=1, 
                                                         sticky=tk.E, pady=5)
        
        self.label_estimation = ttk.Label(main_frame, 
                                          text="Cliquez sur 'Calculer l'estimation'", 
                                          foreground="blue")
        self.label_estimation.grid(row=10, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # ===== SECTION 4: FICHIER DE SORTIE =====
        ttk.Label(main_frame, text="FICHIER DE SORTIE", 
                 font=("Arial", 13, "bold")).grid(row=11, column=0, columnspan=2, 
                                                   sticky=tk.W, pady=(20, 15))
        
        ttk.Label(main_frame, text="Chemin et nom du fichier:").grid(row=12, 
                                                                      column=0, sticky=tk.W)
        ttk.Entry(main_frame, textvariable=self.output_file, 
                 width=50).grid(row=13, column=0, sticky=tk.EW, pady=5)
        ttk.Button(main_frame, text="Parcourir...", 
                  command=self.parcourir_fichier).grid(row=13, column=1, 
                                                       sticky=tk.W, padx=5)
        
        # ===== SECTION 5: PROGRESSION =====
        ttk.Label(main_frame, text="PROGRESSION", 
                 font=("Arial", 13, "bold")).grid(row=14, column=0, columnspan=2, 
                                                   sticky=tk.W, pady=(20, 15))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, 
                                            maximum=100, length=500, mode='determinate')
        self.progress_bar.grid(row=15, column=0, columnspan=2, sticky=tk.EW, pady=5)
        
        self.label_progress = ttk.Label(main_frame, text="Prêt à générer")
        self.label_progress.grid(row=16, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # ===== SECTION 6: BOUTONS =====
        frame_buttons = ttk.Frame(main_frame)
        frame_buttons.grid(row=17, column=0, columnspan=2, sticky=tk.EW, pady=(20, 0))
        
        self.btn_generer = ttk.Button(frame_buttons, text="Générer le dictionnaire", 
                                      command=self.generer_dictionnaire)
        self.btn_generer.pack(side=tk.LEFT, padx=5)
        
        self.btn_stop = ttk.Button(frame_buttons, text="Arrêter", 
                                   command=self.arreter, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        
        # Configurer la colonne pour qu'elle se redimensionne
        main_frame.columnconfigure(1, weight=1)
    
    def parcourir_fichier(self):
        """
        Ouvre une boîte de dialogue pour permettre à l'utilisateur 
        de choisir le fichier de sortie.
        """
        fichier = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
        )
        
        if fichier:
            self.output_file.set(fichier)
    
    def get_caracteres(self):
        """
        Récupère et retourne les caractères sélectionnés par l'utilisateur.
        
        Retour:
            str: Chaîne contenant tous les caractères sélectionnés
        """
        caracteres = ""
        
        if self.use_lowercase.get():
            caracteres += "abcdefghijklmnopqrstuvwxyz"
        
        if self.use_uppercase.get():
            caracteres += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        
        if self.use_digits.get():
            caracteres += "0123456789"
        
        if self.use_special.get():
            caracteres += self.special_chars.get()
        
        return caracteres
    
    def calculer_estimation(self):
        """
        Calcule et affiche une estimation du nombre de mots et de la taille 
        du fichier qui sera généré.
        """
        caracteres = self.get_caracteres()
        
        if not caracteres:
            messagebox.showerror("Erreur", "Veuillez sélectionner au moins un type de caractères!")
            return
        
        min_len = self.min_length.get()
        max_len = self.max_length.get()
        
        if min_len > max_len:
            messagebox.showerror("Erreur", "La longueur minimale ne peut pas dépasser la longueur maximale!")
            return
        
        total = 0
        for length in range(min_len, max_len + 1):
            total += len(caracteres) ** length
        
        avg_length = (min_len + max_len) / 2
        file_size_bytes = total * (avg_length + 1)
        file_size_kb = file_size_bytes / 1024
        file_size_mb = file_size_kb / 1024
        file_size_gb = file_size_mb / 1024
        
        if file_size_gb >= 1:
            size_str = f"{file_size_gb:.2f} GB"
        elif file_size_mb >= 1:
            size_str = f"{file_size_mb:.2f} MB"
        elif file_size_kb >= 1:
            size_str = f"{file_size_kb:.2f} KB"
        else:
            size_str = f"{file_size_bytes:.0f} bytes"
        
        estimation_text = f"Mots: {total:,} | Taille estimée: {size_str}"
        self.label_estimation.config(text=estimation_text, foreground="green")
    
    def generer_dictionnaire(self):
        """
        Valide les paramètres et lance la génération du dictionnaire 
        dans un thread séparé pour ne pas bloquer l'interface.
        """
        if not self.output_file.get():
            messagebox.showerror("Erreur", "Veuillez spécifier un fichier de sortie!")
            return
        
        if self.min_length.get() > self.max_length.get():
            messagebox.showerror("Erreur", "La longueur minimale ne peut pas dépasser la longueur maximale!")
            return
        
        self.creation_en_cours = True
        self.btn_generer.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.progress_var.set(0)
        
        self.thread_generation = Thread(target=self._generer_thread, daemon=True)
        self.thread_generation.start()
    
    def _generer_thread(self):
        """
        Effectue la génération du dictionnaire dans un thread séparé.
        Met à jour la barre de progression et gère les appels à arrêter.
        """
        try:
            min_len = self.min_length.get()
            max_len = self.max_length.get()
            output_file = self.output_file.get()
            caracteres = self.get_caracteres()
            
            if not caracteres:
                messagebox.showerror("Erreur", "Veuillez sélectionner au moins un type de caractères!")
                self.reset_ui()
                return
            
            total = 0
            for length in range(min_len, max_len + 1):
                total += len(caracteres) ** length
            
            count = 0
            start_time = time.time()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                for length in range(min_len, max_len + 1):
                    for combination in itertools.product(caracteres, repeat=length):
                        if not self.creation_en_cours:
                            self.label_progress.config(text="Arrêt demandé par l'utilisateur")
                            self.reset_ui()
                            return
                        
                        mot = ''.join(combination)
                        f.write(mot + '\n')
                        
                        count += 1
                        progress = (count / total) * 100
                        self.progress_var.set(progress)
                        
                        if count % 1000 == 0:
                            elapsed = time.time() - start_time
                            self.label_progress.config(
                                text=f"Progression: {count:,} / {total:,} ({progress:.1f}%) | Temps: {elapsed:.1f}s"
                            )
                            self.root.update()
            
            elapsed = time.time() - start_time
            self.label_progress.config(
                text=f"✓ Généré avec succès: {total:,} mots en {elapsed:.1f}s"
            )
            messagebox.showinfo("Succès", 
                              f"Dictionnaire généré avec succès!\n\n"
                              f"Total de mots: {total:,}\n"
                              f"Temps écoulé: {elapsed:.1f}s\n"
                              f"Fichier: {output_file}")
            
        except IOError as e:
            messagebox.showerror("Erreur", f"Erreur d'accès au fichier:\n{str(e)}")
            self.label_progress.config(text="Erreur lors de la génération")
        except Exception as e:
            messagebox.showerror("Erreur", f"Une erreur est survenue:\n{str(e)}")
            self.label_progress.config(text="Erreur lors de la génération")
        finally:
            self.reset_ui()
    
    def arreter(self):
        """Arrête la génération en cours"""
        self.creation_en_cours = False
        self.btn_stop.config(state=tk.DISABLED)
    
    def reset_ui(self):
        """Réinitialise l'interface après la génération"""
        self.creation_en_cours = False
        self.btn_generer.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)


def main():
    """Fonction principale - Point d'entrée de l'application"""
    root = tk.Tk()
    app = GenerateurDictionnaire(root)
    root.mainloop()


if __name__ == "__main__":
    main()
```

---

## 🔐 Hachages à Solutionner

| # | Hachage bcrypt (10) | Longueur | Caractères |
|---|---|---|---|
| 1 | `$2b$10$yFJlKHNYvr2p9lc.CV78..jSMA8txTD1bP6GwpGgvpiR84TQde03O` | 6 | a b G M 1 2 |
| 2 | `$2b$10$Hh0UhfhtZjrRHdEOxDe3IeYVTnPugoDUtatVDawitU6uTu6tjNDsq` | 6 | 3 |
| 3 | `$2b$10$yZLhRuimD8WcsBWyvgI5Ku2WE5iugYWbDNviN8MyWUYuk29k8q66O` | 6 | a r s m 1 2 |
| 4 | `$2b$10$WNSPHl/HRs9PBuB6MPP2UemGxQZoLwGuLsC0TJRxhW7DPwx2vHPqq` | 6 | a b A B 8 9 |
| 5 | `$2b$10$FfNcnJ5bqVU7soHsTjH27enW31X0XVL/j9mAAvHW8YXhhBqmXr3iq` | 6 | a b c |
| 6 | `$2b$10$.xlm4iEFnb/f7mdrTXW.0ef9ZyfNdg0aIsSoQ/iCrTTUFpqQqwAU6` | 6 | X Y Z |
| 7 | `$2b$10$Pjxp17BVR2jzNtyLlQVvcu0pyoqAdPlZQPNs31cYx2bBXgkFxvwNC` | 7 | (dictionnaire fr) |
| 8 | `$2b$10$9cx9PckWtKsLtDo6ibZdDuDa7EzT6jwD5vQHHWcZvDkho3W90On..` | 8 | (dictionnaire fr) |
| 9 | `$2b$10$wXIcYYgH1eq9WqTJSVc3UOsxvCxCwiV3KbndgNc9IEyxPsUQSixWm` | - | - |
| 10 | `$2b$10$DTW5gstQKZZN6scVuwxf4eBF78PFOij75xv8EdyP3PVrp6i0GmxPa` | - | - |

**Note:** Les hachages #9 et #10 ne sont pas dans le dictionnaire `dico_fr.txt` fourni.

---

## 📊 Résultats Attendus

Après exécution de l'application Partie #2, vous devriez obtenir:

```
Hash: $2b$10$yFJlKHNYvr2p9lc.CV78..jSMA8txTD1bP6GwpGgvpiR84TQde03O
Mot de passe trouvé: [MOT]
Sel: [SEL]
Tentatives: [N]
Temps écoulé: [T]s
```

---

## 📝 Rapport Requis

Le rapport doit contenir:

1. **Page de présentation** - Noms des étudiants, titre, sigle du cours
2. **Implémentation bcrypt** - Explication de l'algorithme utilisé
3. **Présentation des applications** - Langages, classes, fonctions
4. **Solutions des hachages** - Les 10 mots de passe trouvés
5. **Analyse des résultats** - Problèmes, solutions, bons coups
6. **Note de service** - Recommandations pour politique de mots de passe
7. **Conclusion**
8. **Annexes** - Captures d'écran, références

**Limite:** 12 pages (sans annexes)

---

## 🛡️ Bonnes Pratiques de Sécurité

### Ce qu'on NE doit PAS faire:
- ❌ Utiliser MD5 ou SHA1 pour les mots de passe
- ❌ Stocker les mots de passe en clair
- ❌ Utiliser le même sel pour tous les mots de passe
- ❌ Faire trop peu d'itérations de hachage

### Ce qu'on DOIT faire:
- ✅ Utiliser bcrypt, scrypt, ou Argon2
- ✅ Utiliser un sel unique pour chaque mot de passe
- ✅ Utiliser un facteur de coût élevé (10+)
- ✅ Implémenter une politique de mots de passe robuste

---

## 💡 Conseils pour le Rapport

### Note de Service - Recommandations

**Critères minimums pour un mot de passe sécurisé:**

1. **Longueur:** Au minimum 12 caractères (idéalement 16+)
2. **Complexité:** 
   - Au moins une lettre majuscule
   - Au moins une lettre minuscule
   - Au moins un chiffre
   - Au moins un caractère spécial
3. **Unicité:** Différent pour chaque service/application
4. **Renouvellement:** Tous les 90 jours minimum
5. **Pas de patterns:** Éviter dates, noms, suites logiques

**Stockage:**
- Utiliser bcrypt ou Argon2 avec facteur de coût ≥ 10
- Chaque mot de passe doit avoir son propre sel
- Ne JAMAIS utiliser MD5, SHA1, ou SHA256

---

## 📚 Ressources

- **bcrypt Documentation:** https://pypi.org/project/bcrypt/
- **OWASP Password Storage:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **RFC 2104 (HMAC):** https://tools.ietf.org/html/rfc2104
- **Blowfish Algorithm:** https://en.wikipedia.org/wiki/Blowfish_(cipher)

---

## 🤝 Contribution

Ce projet est un travail académique. Les contributions sont limitées aux membres de l'équipe.

---

## 📄 Licence

Ce projet est fourni à titre éducatif dans le cadre du cours INF36207.

---

## ✅ Checklist de Livraison

- [ ] Fichier `README.md` complet
- [ ] Application Partie #1 (générateur) fonctionnelle `.exe`
- [ ] Application Partie #2 (vérificateur) fonctionnelle `.exe`
- [ ] Fichiers `.py` source bien documentés
- [ ] 5 dictionnaires générés (dico_1.txt à dico_5.txt)
- [ ] Rapport de 12 pages max (PDF)
- [ ] Captures d'écran des applications
- [ ] Fichier `rapport_tp.pdf` dans le ZIP
- [ ] Tout dans un fichier ZIP pour Moodle

---

## 📞 Support

**Enseignant:** [Nom de l'enseignant]  
**Email:** [Email du cours]  
**Moodle:** [Lien du cours]

---

**Dernière mise à jour:** 28 janvier 2026  
**Version:** 1.0
