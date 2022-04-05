@echo off
javac .\KeyStoreUtil.java -d .\
jar cfe .\mtkeytool.jar bin.mt.keystore.KeyStoreUtil .\bin\mt\keystore\KeyStoreUtil.class