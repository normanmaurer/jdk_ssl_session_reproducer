# Howto reproduce

```
~ mkdir target
~ javac src/JDKSSLSessionReproducer.java -d target/
~ java -cp src:target JDKSSLSessionReproducer
```

This will produce something like this:

```
Exception in thread "main" java.lang.AssertionError: Should be empty
	at JDKSSLSessionReproducer.main(JDKSSLSessionReproducer.java:77)
```
