# Note d'Information et Prérequis - Audit de Sécurité Active Directory

**Document à l'attention de l'Administration Système et Réseau**

---

## 1. Contexte et Objectif
Dans le cadre de l'évaluation continue de la sécurité de notre système d'information, un audit interne de l'environnement Active Directory (AD) est planifié. L'objectif de cette démarche est d'identifier de manière proactive les erreurs de configuration, les droits excessifs et les vulnérabilités connues (CVE) avant qu'elles ne puissent être exploitées par des acteurs malveillants, afin de renforcer conjointement la sécurité de notre infrastructure.

Le code source complet et la documentation de l'outil d'audit que nous utiliserons sont consultables en toute transparence sur notre dépôt : [Active-Directory-Audit-v1](https://github.com/ZOETYANDE/Active-Directory-Audit-v1).

## 2. Principes d'Exécution et Sécurité de l'Infrastructure
La stabilité et la disponibilité des contrôleurs de domaine (DC) sont notre priorité absolue. L'outil d'audit a été conçu spécifiquement pour les environnements de production et respecte les principes suivants :

*   **Mode "Lecture Seule" (Read-Only) :** L'audit n'effectue **aucune modification** sur l'Active Directory. Il ne crée, ne modifie, ni ne supprime aucun objet, attribut, ou politique.
*   **Approche Non-Destructive :** La recherche de vulnérabilités (ex: PrintNightmare, ZeroLogon, PetitPotam) est effectuée via des requêtes de vérification d'état ou d'énumération RPC, et non par l'exploitation active de failles (aucun risque de *crash* ou de *Blue Screen*).
*   **Contrôle de Charge (Throttling) :** Les requêtes effectuées vers les serveurs sont temporisées afin de prévenir toute surcharge CPU/RAM ou congestion réseau.

## 3. Périmètre Technique de l'Audit
Le framework automatisé effectue une collecte d'informations structurée autour des axes suivants :
1.  **Découverte et Configuration :** Détection des services exposés, versions SMB/LDAP, état de la signature SMB.
2.  **Identités et Accès :** Énumération des utilisateurs, ordinateurs, groupes à privilèges (français et anglais), politiques de mots de passe (GPO/FGPP), et comptes inactifs.
3.  **Délégation et Droits (ACL) :** Cartographie des permissions (BloodHound), AdminSDHolder, délégations Kerberos (Unconstrained, Constrained, RBCD).
4.  **Vulnérabilités et Hardening :** Vérification des correctifs de sécurité critiques (ZeroLogon, PetitPotam, etc.), configuration LAPS, et sécurité des services de certificats (ADCS).
5.  **Réseau et Partages :** Évaluation des accès anonymes, énumération DNS, et analyse des partages SYSVOL.

## 4. Outils Techniques Utilisés
L'audit s'appuie sur des outils standards de l'industrie de la cybersécurité, fonctionnant depuis une machine d'audit locale :
*   `nmap` (Découverte réseau et détection des services exposés).
*   `ldapsearch` (Interrogation native de l'annuaire LDAP).
*   `bloodhound-python` / `impacket` (Cartographie des chemins d'attaque et des dépendances de droits).
*   `nxc` (NetExec), `enum4linux-ng` et `smbclient` (Énumération SMB, accès aux partages et vérifications de configurations).
*   `dig` (Vérification de la sécurité de la zone DNS : transferts de zone, etc.).
*   `certipy` (Analyse de la configuration ADCS - si applicable).

## 5. Prérequis pour la Réalisation de l'Audit
Afin de réaliser cet audit dans des conditions optimales, les éléments suivants sont requis de la part de l'équipe système :

1.  **Un Compte Utilisateur Standard :** Un compte du domaine (ex: `audit.ad`) sans **aucun privilège particulier** (pas de droits d'administration, membre uniquement du groupe par défaut "Utilisateurs du domaine").
2.  **Visibilité Réseau :** La machine de l'auditeur doit pouvoir joindre le(s) Contrôleur(s) de Domaine sur les ports standards de l'AD (notamment TCP/UDP 53, 88, 135, 139, 445, 389, 636, 3268, 3269).
3.  **Fenêtre d'Intervention :** Une plage horaire validée conjointement (idéalement en dehors des pics d'authentification massifs de début de journée).

---
*Nous restons à votre entière disposition pour une revue technique détaillée du script, de ses modules et de son code source avant toute exécution.*
