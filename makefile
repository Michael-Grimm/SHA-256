unittests: aliases makros.sx sha256.sx sha256tests.sx sha256tests.c 
	gcc -g -o sha256.unittests sha256.sx sha256tests.sx sha256tests.c  
	./sha256.unittests


build: libSha256.a


libSha256.a: sha256.o 
	ar rcs libSha256.a  sha256.o 


sha256.o: sha256.sx aliases makros.sx
	gcc -c -o sha256.o sha256.sx   
	
dump: sha256.o
	objdump -S -M no-aliases -s -d sha256.o > dump.txt
 

dump2: sha256.o
	objdump -s sha256.o > dump2.txt
 
	
	









	
