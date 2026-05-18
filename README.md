# LAB 15 : Analyse Dynamique Android — Inspection TLS/HTTPS et Bypass SSL Pinning

---

## Mon setup de départ

Pour ce lab j'avais besoin de tout mettre en place from scratch. Mon environnement :

- Windows 11, Python 3.10.6
- Appareil Android x86 (émulateur AVD)
- Burp Suite Community 2024
- Frida 17.9.1

Premier réflexe avant de commencer, vérifier que tout est bien installé :

```
python --version
pip --version
adb version
frida --version
```
<img width="1042" height="142" alt="image" src="https://github.com/user-attachments/assets/4c51d308-b446-4f07-bd1e-e79974abcedc" />

---

## Étape 1 — Mise en place de Frida

### Installation côté PC

Rien de compliqué ici, une seule commande suffit :

```
python -m pip install --upgrade frida frida-tools
```

Ensuite je vérifie que tout est là :

```
frida --version
python -c "import frida; print(frida.__version__)"
```
<img width="1467" height="382" alt="image" src="https://github.com/user-attachments/assets/c74db48c-e7c4-4e83-8feb-37b9de319d3e" />

### Déploiement de frida-server sur l'appareil

Première chose à faire : connaître l'architecture de l'appareil avant de télécharger le mauvais binaire (erreur classique).

```
adb shell getprop ro.product.cpu.abi
```
<img width="1057" height="316" alt="image" src="https://github.com/user-attachments/assets/ceb74732-f2cd-4493-af35-7f1883ffbdac" />


Ça me retourne x86, donc je télécharge frida-server-17.9.1-android-x86 depuis les releases GitHub de Frida. Je le transfère et je le lance :

```
adb push frida-server-17.9.1-android-x86 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server -l 0.0.0.0"
```

Je vérifie ensuite que les processus remontent bien :

```
frida-ps -Uai
```
<img width="1007" height="556" alt="image" src="https://github.com/user-attachments/assets/47072cfb-1329-43d3-9d6e-b859f6001cfc" />

Point important que j'ai appris à mes dépens : la version de frida-server doit être **exactement** la même que le client installé sur le PC. Sinon connexion impossible.

---

## Étape 2 — Proxy TLS et certificat CA

### Lancer Burp Suite

J'ouvre Burp Suite, je vais dans Proxy > Options et je configure le listener sur toutes les interfaces, port 8080. Je note l'adresse IP de ma machine sur le réseau local.

### Installer le certificat CA sur l'appareil

Depuis le navigateur du téléphone j'accède à `http://burp` et je télécharge le certificat. Je l'installe en tant que CA utilisateur depuis les paramètres Android.

Problème connu sur Android 7+ : les apps ignorent les CA utilisateur par défaut à cause du Network Security Config. C'est précisément pour ça qu'on va hooker TrustManager avec Frida plutôt que de compter uniquement sur le certificat.

### Redirection du trafic

J'utilise la méthode USB via adb reverse, plus fiable que le proxy Wi-Fi :
<img width="826" height="562" alt="image" src="https://github.com/user-attachments/assets/65f16b2d-83c3-4969-8892-71cd5beeecb7" />
<img width="285" height="582" alt="image" src="https://github.com/user-attachments/assets/ec9c1492-984b-4f46-b222-2a95e8e18998" />
```
adb reverse tcp:8080 tcp:8080
```

---

## Étape 3 — Lancement de l'app sous Frida

Pour identifier le package exact de l'app cible :

```
frida-ps -Uai
```

Je lance en mode spawn parce que le pinning est souvent initialisé très tôt au démarrage, avant même que l'app soit attachable :

```
frida -U -f com.package.cible -l script.js --no-pause
```

---

## Étape 4 — Script de bypass SSL Pinning (couche Java)

J'ai écrit mon script en couvrant les cas les plus fréquents rencontrés dans les apps réelles.

Ce que le script fait :
- Injecte un TrustManager permissif dans SSLContext.init
- Patche toutes les classes contenant "trust" ou "pin" dans leur nom
- Cible spécifiquement Conscrypt TrustManagerImpl pour Android 7+
- Neutralise OkHttp CertificatePinner
- Force WebView à ignorer les erreurs SSL

```javascript
Java.perform(function(){

  // TrustManager permissif injecté dans SSLContext.init
  try {
    const SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;',
      '[Ljavax.net.ssl.TrustManager;',
      'java.security.SecureRandom'
    ).implementation = function(km, tm, sr) {
      console.log('[+] SSLContext.init intercepté');
      return this.init(km, tm, sr);
    };
  } catch(e) { console.log('[-] SSLContext échoué : ' + e.message); }

  // Patch large de tous les TrustManager chargés
  Java.enumerateLoadedClasses({
    onMatch: function(name) {
      if (name.toLowerCase().includes('trust') || name.toLowerCase().includes('pin')) {
        try {
          const K = Java.use(name);
          ['checkServerTrusted', 'checkClientTrusted'].forEach(function(m) {
            if (K[m]) K[m].overloads.forEach(function(ov) {
              ov.implementation = function() {
                console.log('[+] Bypassed : ' + name + '.' + m);
                return null;
              };
            });
          });
        } catch(_) {}
      }
    },
    onComplete: function() { console.log('[+] Scan TrustManager terminé'); }
  });

  // Conscrypt Android 7+
  ['com.android.org.conscrypt.TrustManagerImpl', 'org.conscrypt.TrustManagerImpl'].forEach(function(cls) {
    try {
      const TMI = Java.use(cls);
      ['checkTrusted', 'verifyChain', 'checkServerTrusted'].forEach(function(m) {
        if (TMI[m]) TMI[m].overloads.forEach(function(ov) {
          ov.implementation = function() {
            console.log('[+] ' + cls + '.' + m + ' -> ignoré');
            return null;
          };
        });
      });
    } catch(e) {}
  });

  // OkHttp CertificatePinner
  try {
    const CP = Java.use('okhttp3.CertificatePinner');
    if (CP.check) CP.check.overloads.forEach(function(ov) {
      ov.implementation = function() {
        console.log('[+] OkHttp CertificatePinner.check -> skip');
      };
    });
  } catch(e) {}

  // WebView SSL errors
  try {
    const WVC = Java.use('android.webkit.WebViewClient');
    WVC.onReceivedSslError.implementation = function(view, handler, error) {
      console.log('[+] WebView SSL error ignoré');
      handler.proceed();
    };
  } catch(e) {}

  console.log('[*] Bypass SSL Pinning installé');
});
```

Je l'injecte sur l'app cible :

```
frida -U -f owasp.mstg.uncrackable3 -l sslpin_bypass.js --no-pause
```

Dans la console je vois les logs `[+] Bypassed` s'afficher à chaque connexion HTTPS tentée par l'app. Côté Burp, les requêtes commencent à apparaître en clair.

---

## Étape 5 — Variantes selon le contexte

Si l'app utilise uniquement OkHttp, le bloc CertificatePinner suffit. Si le package est renommé (obfuscation), je cherche d'abord dans le REPL Frida :

```javascript
Java.enumerateLoadedClasses({
  onMatch: function(name) {
    if (name.toLowerCase().includes('okhttp')) console.log(name);
  },
  onComplete: function() {}
});
```

Pour les apps qui sont principalement des WebViews, le hook `onReceivedSslError` couvre la majorité des cas sans avoir besoin de toucher à TrustManager.

---

## Étape 6 — Cas avancé : pinning natif BoringSSL/OpenSSL

Quand aucune requête ne passe dans le proxy malgré le script Java, c'est que le pinning est fait dans une lib native. J'ai utilisé frida-trace pour découvrir quels symboles SSL sont appelés :

```
frida-trace -U -i SSL_* -i X509_* owasp.mstg.uncrackable3
```

Je repère notamment `SSL_get_verify_result` et `X509_verify_cert` dans la trace. Je crée un second script pour hooker au niveau natif :

```javascript
function hookNatif(nom, lib) {
  const addr = Module.findExportByName(lib || null, nom);
  if (!addr) {
    console.log('[*] Symbole non trouvé : ' + nom);
    return;
  }
  Interceptor.attach(addr, {
    onLeave: function(rv) {
      if (nom === 'SSL_get_verify_result') {
        rv.replace(ptr(0)); // 0 = X509_V_OK = certificat valide
        console.log('[+] SSL_get_verify_result patché -> X509_V_OK');
      }
    }
  });
  console.log('[+] Hook natif appliqué sur : ' + nom);
}

hookNatif('SSL_get_verify_result', 'libssl.so');
```

Je lance les deux scripts ensemble :

```
frida -U -f owasp.mstg.uncrackable3 -l sslpin_bypass.js -l sslpin_bypass_native.js --no-pause
```
<img width="902" height="312" alt="image" src="https://github.com/user-attachments/assets/616fc3aa-7cda-4d97-83b5-924ab62b8968" />

J'ai eu un crash SIGABRT sur ce test. Ce que ça m'indique c'est que la lib native détecte la manipulation — il faut ajuster et cibler plutôt `SSL_set_custom_verify` ou le callback personnalisé installé par l'app. Les noms de symboles varient aussi selon la version Android et la lib embarquée dans l'APK, donc c'est du cas par cas.

---

## Ce que j'ai retenu

- Le certificat CA seul ne suffit pas sur Android 7+ à cause du Network Security Config
- Il faut hooker TrustManager en Java pour les apps qui font leur pinning côté JVM
- Conscrypt est le point de contrôle principal sur les versions Android récentes, pas SSLContext directement
- Quand le proxy ne reçoit rien malgré les hooks Java, c'est presque toujours du natif — frida-trace est le premier réflexe
- Les crashs natifs sont normaux au début, ils indiquent juste qu'il faut affiner le point d'accroche dans la lib
