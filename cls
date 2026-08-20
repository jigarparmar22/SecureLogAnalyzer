[1mdiff --git a/.gitignore b/.gitignore[m
[1mindex ec1077e..9943373 100644[m
[1m--- a/.gitignore[m
[1m+++ b/.gitignore[m
[36m@@ -5,4 +5,8 @@[m [mvenv/[m
 .env[m
 database/logs.db[m
 uploads/[m
[31m-.vscode/[m
\ No newline at end of file[m
[32m+[m[32mreports/[m
[32m+[m[32m.vscode/[m
[32m+[m[32m.idea/[m
[32m+[m[32m.DS_Store[m
[32m+[m[32m*.log[m
[1mdiff --git a/config.py b/config.py[m
[1mindex 80a9a27..1052c1e 100644[m
[1m--- a/config.py[m
[1m+++ b/config.py[m
[36m@@ -1,10 +1,27 @@[m
[32m+[m[32mimport os[m
[32m+[m
[32m+[m
 class Config:[m
[31m-    SECRET_KEY = "secure-log-analyzer-key"[m
[32m+[m[32m    # Read the secret key from the environment.[m
[32m+[m[32m    # A development-only fallback is provided so the app can run locally,[m
[32m+[m[32m    # but production deployments MUST set SECRET_KEY.[m
[32m+[m[32m    SECRET_KEY = os.environ.get([m
[32m+[m[32m        "SECRET_KEY",[m
[32m+[m[32m        "dev-only-insecure-secret-change-me"[m
[32m+[m[32m    )[m
 [m
[31m-    UPLOAD_FOLDER = "uploads"[m
[32m+[m[32m    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")[m
 [m
[31m-    MAX_CONTENT_LENGTH = 100* 1024 * 1024[m
[32m+[m[32m    REPORT_FOLDER = os.environ.get("REPORT_FOLDER", "reports")[m
[32m+[m
[32m+[m[32m    MAX_CONTENT_LENGTH = 100 * 1024 * 1024[m
 [m
     ALLOWED_EXTENSIONS = {"xml"}[m
 [m
[31m-    DATABASE = "database/logs.db"[m
\ No newline at end of file[m
[32m+[m[32m    DATABASE = os.environ.get("DATABASE", "database/logs.db")[m
[32m+[m
[32m+[m[32m    # Secure session cookie defaults.[m
[32m+[m[32m    SESSION_COOKIE_HTTPONLY = True[m
[32m+[m[32m    SESSION_COOKIE_SAMESITE = "Lax"[m
[32m+[m[32m    # Enable in production over HTTPS.[m
[32m+[m[32m    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"[m
\ No newline at end of file[m
[1mdiff --git a/requirements.txt b/requirements.txt[m
[1mindex 2eafb1c..a7abd54 100644[m
[1m--- a/requirements.txt[m
[1m+++ b/requirements.txt[m
[36m@@ -3,6 +3,7 @@[m [mclick==8.4.2[m
 colorama==0.4.6[m
 contourpy==1.3.3[m
 cycler==0.12.1[m
[32m+[m[32mdefusedxml==0.7.1[m
 Flask==3.1.3[m
 Flask-SQLAlchemy==3.1.1[m
 fonttools==4.63.0[m
[36m@@ -18,8 +19,9 @@[m [mpandas==3.0.3[m
 pillow==12.3.0[m
 pyparsing==3.3.2[m
 python-dateutil==2.9.0.post0[m
[32m+[m[32mreportlab==4.2.5[m
 six==1.17.0[m
 SQLAlchemy==2.0.51[m
 typing_extensions==4.16.0[m
 tzdata==2026.3[m
[31m-Werkzeug==3.1.8[m
[32m+[m[32mWerkzeug==3.1.8[m
\ No newline at end of file[m
