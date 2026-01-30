# 🩸 BloodHound Collector

Scripts simplifiés pour la collecte de données Active Directory avec BloodHound.

## 📋 Description

**BloodHound Collector** automatise la collecte de données AD pour l'analyse des chemins d'attaque. Le script détecte automatiquement le domaine et configure la résolution DNS.

## ✨ Fonctionnalités

- 🔍 **Auto-détection du domaine** via LDAP, nmap ou netexec
- 🔐 **Saisie sécurisée** du mot de passe (invisible)
- 🌐 **Configuration DNS automatique** (ajout /etc/hosts)
- 📦 **Export ZIP** prêt pour BloodHound GUI

## 🚀 Installation

```bash
# Cloner le repo
git clone https://github.com/votre-username/bloodhound-collector.git
cd bloodhound-collector

# Installer les dépendances
sudo ./B_Collector.sh
```

## 📖 Utilisation

```bash
./B_Collector.sh <username> <dc_ip>
```

**Exemple :**
```bash
./B_Collector.sh admin 192.168.1.10
Password: ********

[*] Détection du domaine AD...
[✓] Domaine détecté: corp.local
[✓] DC: dc01.corp.local
[*] 🚀 Collecte en cours...
[✓] Collecte réussie!
```

## 📁 Fichiers

| Fichier | Description |
|---------|-------------|
| `B_collector.sh` | Script principal de collecte |
| `requirements.sh` | Installateur des dépendances |

## 🔧 Dépendances

- bloodhound-python
- impacket
- ldap3
- ldap-utils
- nmap

## 📊 Résultats

Les fichiers générés se trouvent dans `./bloodhound_YYYYMMDD_HHMMSS/` :
- `*.json` - Données brutes (users, groups, computers, etc.)
- `*.zip` - Archive prête pour import BloodHound

## 🎯 Prochaines étapes

1. Ouvrir **BloodHound GUI** ou **BloodHound CE**
2. Importer le fichier `.zip`
3. Analyser les chemins vers Domain Admin

## ⚠️ Avertissement

Cet outil est destiné aux tests d'intrusion autorisés et aux audits de sécurité. Utilisez-le uniquement sur des systèmes pour lesquels vous avez une autorisation explicite.

## 📜 Licence

MIT License
