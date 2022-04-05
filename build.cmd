@echo off
javac .\bin\mt\keystore\KeyStoreUtil.java
del .\bin\mt\keystore\KeyStoreUtil.java
jar cfe .\mtkeytool.jar bin.mt.keystore.KeyStoreUtil .\bin\mt\keystore\KeyStoreUtil.class