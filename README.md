"""
================================================================================
GENERATEUR DE DICTIONNAIRE DE MOTS DE PASSE
Travail Pratique - Securite Informatique INF36207
================================================================================
Application de generation de dictionnaires pour attaques par force brute.
Permet de generer toutes les combinaisons possibles selon les parametres donnes.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import itertools
from threading import Thread
from datetime import datetime
import time


class GenerateurDictionnaire:
    """
    Classe principale pour la generation de dictionnaires de mots de passe.
    
    Interface graphique permettant a l'utilisateur de:
    - Definir les longueurs min/max des mots
    - Choisir les caracteres a utiliser
    - Estimer la taille du dictionnaire
    - Generer et sauvegarder le dictionnaire dans un fichier
    """
    
    def __init__(self, root):
        """Initialise la fenetre principale et les variables"""
        self.root = root
        self.root.title("Generateur de Dictionnaire de Mots de Passe")
        self.root.geometry("700x800")
        self.root.resizable(False, False)
        
        # Variables pour stocker les valeurs saisies
        self.min_length = tk.IntVar(value=1)
        self.max_length = tk.IntVar(value=3)
        self.output_file = tk.StringVar()
        self.caracteres = tk.StringVar()
        
        # Checkboxes pour les types de caracteres
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_uppercase = tk.BooleanVar(value=False)
        self.use_digits = tk.BooleanVar(value=False)
        self.use_special = tk.BooleanVar(value=False)
        self.special_chars = tk.StringVar(value="#$%?&*")
        
        # Flags pour controler la generation
        self.creation_en_cours = False
        self.thread_generation = None
        
        # Construire l'interface
        self.build_ui()
    
    def build_ui(self):
        """Construit l'interface graphique de l'application"""
        
        # Frame principal avec padding
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # SECTION 1: LONGUEURS DES MOTS
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
        
        # SECTION 2: CARACTERES PERMIS
        ttk.Label(main_frame, text="CARACTERES PERMIS", 
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
        
        ttk.Checkbutton(main_frame, text="Caracteres speciaux", 
                       variable=self.use_special).grid(row=7, column=0, 
                                                       columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Label(main_frame, text="Caracteres speciaux (personnalises):").grid(
            row=8, column=0, sticky=tk.W, pady=(10, 5))
        ttk.Entry(main_frame, textvariable=self.special_chars, 
                 width=40).grid(row=8, column=1, sticky=tk.EW)
        
        # SECTION 3: ESTIMATION
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
        
        # SECTION 4: FICHIER DE SORTIE
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
        
        # SECTION 5: PROGRESSION
        ttk.Label(main_frame, text="PROGRESSION", 
                 font=("Arial", 13, "bold")).grid(row=14, column=0, columnspan=2, 
                                                   sticky=tk.W, pady=(20, 15))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, 
                                            maximum=100, length=500, mode='determinate')
        self.progress_bar.grid(row=15, column=0, columnspan=2, sticky=tk.EW, pady=5)
        
        self.label_progress = ttk.Label(main_frame, text="Pret a generer")
        self.label_progress.grid(row=16, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # SECTION 6: BOUTONS
        frame_buttons = ttk.Frame(main_frame)
        frame_buttons.grid(row=17, column=0, columnspan=2, sticky=tk.EW, pady=(20, 0))
        
        self.btn_generer = ttk.Button(frame_buttons, text="Generer le dictionnaire", 
                                      command=self.generer_dictionnaire)
        self.btn_generer.pack(side=tk.LEFT, padx=5)
        
        self.btn_stop = ttk.Button(frame_buttons, text="Arreter", 
                                   command=self.arreter, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        
        # Configurer la colonne pour qu'elle se redimensionne
        main_frame.columnconfigure(1, weight=1)
    
    def parcourir_fichier(self):
        """
        Ouvre une boite de dialogue pour permettre a l'utilisateur 
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
        Recupere et retourne les caracteres selectionnes par l'utilisateur.
        
        Retour:
            str: Chaine contenant tous les caracteres selectionnes
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
        du fichier qui sera genere.
        """
        caracteres = self.get_caracteres()
        
        if not caracteres:
            messagebox.showerror("Erreur", "Veuillez selectionner au moins un type de caracteres!")
            return
        
        min_len = self.min_length.get()
        max_len = self.max_length.get()
        
        if min_len > max_len:
            messagebox.showerror("Erreur", "La longueur minimale ne peut pas depasser la longueur maximale!")
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
        
        estimation_text = f"Mots: {total:,} | Taille estimee: {size_str}"
        self.label_estimation.config(text=estimation_text, foreground="green")
    
    def generer_dictionnaire(self):
        """
        Valide les parametres et lance la generation du dictionnaire 
        dans un thread separe pour ne pas bloquer l'interface.
        """
        if not self.output_file.get():
            messagebox.showerror("Erreur", "Veuillez specifier un fichier de sortie!")
            return
        
        if self.min_length.get() > self.max_length.get():
            messagebox.showerror("Erreur", "La longueur minimale ne peut pas depasser la longueur maximale!")
            return
        
        self.creation_en_cours = True
        self.btn_generer.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.progress_var.set(0)
        
        self.thread_generation = Thread(target=self._generer_thread, daemon=True)
        self.thread_generation.start()
    
    def _generer_thread(self):
        """
        Effectue la generation du dictionnaire dans un thread separe.
        Met a jour la barre de progression et gere les appels a arreter.
        """
        try:
            min_len = self.min_length.get()
            max_len = self.max_length.get()
            output_file = self.output_file.get()
            caracteres = self.get_caracteres()
            
            if not caracteres:
                messagebox.showerror("Erreur", "Veuillez selectionner au moins un type de caracteres!")
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
                            self.label_progress.config(text="Arret demande par l'utilisateur")
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
                text=f"Genere avec succes: {total:,} mots en {elapsed:.1f}s"
            )
            messagebox.showinfo("Succes", 
                              f"Dictionnaire genere avec succes!\n\n"
                              f"Total de mots: {total:,}\n"
                              f"Temps ecoule: {elapsed:.1f}s\n"
                              f"Fichier: {output_file}")
            
        except IOError as e:
            messagebox.showerror("Erreur", f"Erreur d'acces au fichier:\n{str(e)}")
            self.label_progress.config(text="Erreur lors de la generation")
        except Exception as e:
            messagebox.showerror("Erreur", f"Une erreur est survenue:\n{str(e)}")
            self.label_progress.config(text="Erreur lors de la generation")
        finally:
            self.reset_ui()
    
    def arreter(self):
        """Arrete la generation en cours"""
        self.creation_en_cours = False
        self.btn_stop.config(state=tk.DISABLED)
    
    def reset_ui(self):
        """Reinitialise l'interface apres la generation"""
        self.creation_en_cours = False
        self.btn_generer.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)


def main():
    """Fonction principale - Point d'entree de l'application"""
    root = tk.Tk()
    app = GenerateurDictionnaire(root)
    root.mainloop()


if __name__ == "__main__":
    main()

