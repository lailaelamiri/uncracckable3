# OWASP MAS UnCrackable Level 3 — Rapport de Lab

> **Objectif** : Contourner toutes les protections natives et Java de l'application Android *UnCrackable Level 3* et retrouver la chaîne secrète `making owasp great again`.

---

## Environnement

| Élément | Valeur |
|---|---|
| Application | OWASP MAS UnCrackable Level 3 |
| Package | `owasp.mstg.uncrackable3` |
| Architecture émulateur | x86_64 (+ armeabi-v7a, arm64-v8a, x86) |
| Outils principaux | apktool, apksigner, zipalign, Python 3, capstone, pyelftools |

---

## Vue d'ensemble des protections

L'application implémente **cinq couches de protection** distinctes :

| # | Protection | Couche | Mécanisme |
|---|---|---|---|
| 1 | Root detection | Java | `RootDetection.checkRoot1/2/3()` |
| 2 | Debuggability check | Java | `IntegrityCheck.isDebuggable()` |
| 3 | Integrity check (CRC) | Java/Native | `verifyLibs()` compare CRC32 des `.so` et `classes.dex` |
| 4 | Anti-debug thread | Native | `.init_array` lance un thread qui scanne `/proc/self/maps` (Frida/Xposed) → `goodbye()` |
| 5 | Anti-ptrace (fork monitor) | Native | `fork()` crée un processus enfant qui appelle `ptrace(PTRACE_SEIZE)` sur le parent ; si le parent est tracé → `ptrace(KILL)` = SIGKILL |

La vérification du code secret se fait dans `bar()` (natif) avec un compteur d'initialisation supplémentaire.

---

## Étape 1 — Décompilation avec apktool

```bash
apktool d UnCrackable-Level3.apk -o uncrackable3/
```

Structure obtenue :
```
uncrackable3/
├── smali/sg/vantagepoint/uncrackable3/
│   └── MainActivity.smali
├── lib/
│   ├── x86/libfoo.so
│   ├── x86_64/libfoo.so
│   ├── armeabi-v7a/libfoo.so
│   └── arm64-v8a/libfoo.so
└── res/values/strings.xml
```
<img width="1204" height="287" alt="Screenshot 2026-05-18 115936" src="https://github.com/user-attachments/assets/1204a867-06b7-4fa2-9eae-faf4247facf2" />

---

## Étape 2 — Patch Smali (couches Java)

### 2.1 Supprimer le popup « Rooting or tampering detected »

Fichier : `smali/sg/vantagepoint/uncrackable3/MainActivity.smali`

Dans la méthode `onCreate`, remplacer :

```smali
const-string v0, "Rooting or tampering detected."
invoke-direct {p0, v0}, Lsg/vantagepoint/uncrackable3/MainActivity;->showDialog(Ljava/lang/String;)V
```

Par :

```smali
return-void
```

### 2.2 Neutraliser les vérifications CRC dans `verifyLibs()`

`verifyLibs()` calcule le CRC32 de chaque `.so` et de `classes.dex`, puis compare aux valeurs stockées dans `strings.xml`. Plutôt que de maintenir les CRC en synchronisation (circulaire), on patch directement les branchements conditionnels :

```smali
# Vérification CRC des .so  (ligne ~334)
# AVANT :
if-eqz v12, :cond_0
# APRÈS :
goto :cond_0

# Vérification CRC de classes.dex  (ligne ~414)
# AVANT :
if-eqz v3, :cond_2
# APRÈS :
goto :cond_2
```

Ces deux `goto` font que `tampered` reste à 0 quelles que soient les modifications apportées aux binaires.

<img width="1839" height="1002" alt="Screenshot 2026-05-18 115033" src="https://github.com/user-attachments/assets/a9286a96-3569-466b-acc4-3b22b83acece" />

---

## Étape 3 — Analyse de `libfoo.so` (Ghidra / capstone)

### Fonctions clés identifiées

| Fonction | Adresse (x86) | Rôle |
|---|---|---|
| `goodbye()` | `0x3000` | `raise(SIGKILL)` + `_exit(0)` — tue le processus |
| `.init_array[0]` | `0x3180` | Lance le thread `/proc/self/maps` (anti-Frida) |
| Thread `/proc/maps` | `0x3080` | Boucle `fgets` cherchant "frida"/"xposed" → `goodbye()` |
| `init()` (JNI) | `0x3320` | Copie la clé pizza en mémoire, incrémente compteur |
| Fonction fork | `0x3250` | `fork()` → enfant appelle `ptrace(SEIZE, ppid)` → surveille le parent |
| `baz()` (JNI) | `0x3390` | Retourne le CRC attendu de `classes.dex` |
| `bar()` (JNI) | `0x33b0` | Vérification du code secret par XOR |

### Schéma d'appel

```
JNI_OnLoad / .init_array
    └── 0x3180 → pthread_create(thread_maps @ 0x3080)
                    └── scan /proc/self/maps → goodbye() si Frida

Java: onCreate()
    └── verifyLibs()   ← CRC check (patché en smali)
    └── init(pizza_key)
            └── 0x3250 → fork()
                            └── enfant: ptrace(SEIZE, parent) → kill si débogué
            └── copie pizza_key → [ebx+0x78]
            └── inc [ebx+0x94]   ← compteur init = 1

Java: verify(input)
    └── CodeCheck.bar(input.getBytes())
            └── check [ebx+0x94] == 1   ← compteur
            └── LCG obfuscation → 24 octets XOR mask
            └── input[i] XOR lcg[i] == pizza_key[i] ?
```

---

## Étape 4 — Patch natif de `libfoo.so` (4 architectures)

Les patches sont appliqués à **x86, armeabi-v7a, arm64-v8a et x86_64**.

### Patch 1 — `goodbye()` → RET immédiat

Neutralise la fonction qui envoie SIGKILL.

| Arch | Offset | Avant | Après |
|---|---|---|---|
| x86 | `0x3000` | `55` (push ebp) | `C3` (RET) |
| armeabi-v7a | `0x238c` | `80 B5` (PUSH {r7,lr}) | `70 47` (BX LR) |
| arm64-v8a | `0x3080` | `FD 7B BF A9` | `C0 03 5F D6` (RET) |
| x86_64 | `0x3740` | `50` (push rax) | `C3` (RET) |

### Patch 2 — `fork()` → retourne -1 (pas d'enfant)

Empêche la création du processus enfant ptrace.

| Arch | Offset | Avant | Après |
|---|---|---|---|
| x86 | `0x3272` | `E8 19 D7 FF FF` (call fork) | `31 C0 48 90 90` (xor eax,eax; dec eax) |
| armeabi-v7a | `0x24D0` | `FE F7 CC EB` (BLX fork) | `00 BF 00 BF` (NOP×2) |
| arm64-v8a | `0x3258` | `C2 F6 FF 97` (BL fork) | `1F 20 03 D5` (NOP) |
| x86_64 | `0x3925` | `E8 16 D4 FF FF` (call fork) | `31 C0 48 90 90` |

### Patch 3 — `.init_array` → RET immédiat

Arrête le thread de scan `/proc/self/maps`.

| Arch | Offset | Avant | Après |
|---|---|---|---|
| x86 | `0x3180` | `C3` | déjà patché ✓ |
| armeabi-v7a | `0x2468` | `BC B5` | `70 47` (BX LR) |
| arm64-v8a | `0x31B0` | `FF C3 00 D1` | `C0 03 5F D6` (RET) |
| x86_64 | `0x38A0` | `48 83 EC 18` | `C3` (RET) |

### Patch 4 — `bar()` compteur : `== 2` → `== 1`

**Cause racine du "Nope"** : `bar()` vérifie que le compteur d'initialisation vaut 2 (incrémenté par `init()` + par la fonction `.init_array`). Comme on a patché `.init_array` à RET, le compteur ne vaut que 1. On change la comparaison.

| Arch | Offset | Avant | Après |
|---|---|---|---|
| x86 | `0x33F4` | `02` | `01` |
| armeabi-v7a | `0x25D0` | `02 28` (cmp r0,#2) | `01 28` (cmp r0,#1) |
| arm64-v8a | `0x33E8` | `1F 09 00 71` (cmp w8,#2) | `1F 05 00 71` (cmp w8,#1) |
| x86_64 | `0x3A99` | `...02` | `...01` |

---

## Étape 5 — Extraction de la clé secrète

### Algorithme de `bar()`

```
stored_key[24] = init(pizza_key)   # "pizzapizzapizzapizzapizz"
lcg_buf[24]    = obfuscation_LCG() # seed fixe → déterministe

for i in range(24):
    if input[i] XOR lcg_buf[i] != stored_key[i]:
        return False
return True
```

### Décodage

Les 24 octets encodés extraits du binaire (constantes dans `FUN_001012c0`) :

```
1d 08 11 13 0f 17 49 15  0d 00 03 19 5a 1d 13 15
08 0e 5a 00 17 08 13 14
```

Script de décodage :

```python
encoded = bytes.fromhex("1d0811130f1749150d0003195a1d1315080e5a0017081314")
xor_key = b"pizzapizzapizzapizzapizz"  # 24 octets

secret = bytes(a ^ b for a, b in zip(encoded, xor_key))
print(secret.decode())  # → making owasp great again
```

**Clé secrète : `making owasp great again`**

---

## Étape 6 — Reconstruction et signature de l'APK

```bash
# Reconstruction avec apktool
apktool b uncrackable3/ -o UnCrackable-Level3-patched.apk --use-aapt2

# Alignement
zipalign -f 4 UnCrackable-Level3-patched.apk UnCrackable-Level3-aligned.apk

# Signature avec le keystore de debug
apksigner sign \
    --ks "%USERPROFILE%\.android\debug.keystore" \
    --ks-key-alias androiddebugkey \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out UnCrackable-Level3-signed.apk \
    UnCrackable-Level3-aligned.apk

# Désinstaller l'ancienne version
adb uninstall owasp.mstg.uncrackable3

# Installation
adb install UnCrackable-Level3-signed.apk
```

---

<img width="297" height="575" alt="Screenshot 2026-05-22 171858" src="https://github.com/user-attachments/assets/f3c9b2c9-9618-4ad3-ad1d-ec388a7af656" />

## Résultat final

```
Input  : making owasp great again
Résultat :   Success! — This is the correct secret.
```

---

## Résumé des techniques de protection et contournements

| Protection | Technique | Contournement |
|---|---|---|
| Root/debug detection | Java checks | Patch smali `return-void` |
| CRC integrity check | `verifyLibs()` Java | Patch `if-eqz` → `goto` (bypass conditionnel) |
| Anti-Frida thread | `/proc/self/maps` scan natif | `.init_array` → RET (thread jamais lancé) |
| Anti-ptrace | `fork()` + `ptrace(SEIZE)` enfant | `fork()` → retourne -1 (pas d'enfant) |
| SIGKILL | `goodbye()` natif | `goodbye()` → RET immédiat |
| Compteur d'init | `bar()` vérifie counter==2 | Changer comparaison `==2` → `==1` |
| Secret obfusqué | XOR + LCG natif | Extraction statique des constantes + XOR pizza |

---

## Apprentissages clés

**1. Suivre le flux de données, pas le code parasite.**
La fonction `FUN_001012c0` contient ~90 malloc/LCG répétitifs (obfuscation Tigress/OLLVM). La donnée utile est dans les dernières écritures vers `param_1`.

**2. Les protections natives sont circulaires.**
Patcher le `.so` change son CRC → `tampered=31337` → popup. Il faut patcher *aussi* le mécanisme de vérification CRC, ou bypasser le check en smali.

**3. Chaque patch peut en casser un autre.**
Patcher `.init_array` à RET a cassé le compteur dans `bar()`. Il faut tracer toutes les dépendances entre les composants.

**4. `goodbye()` n'est que la surface.**
Il y a deux chemins vers SIGKILL : le thread `/proc/maps` ET le processus enfant ptrace. Les deux doivent être neutralisés.
