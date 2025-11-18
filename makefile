test1: clean
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo "1) Testing STUDENT's Amal against REFERENCE's KDC+Basim"
	@echo "   Validates   M1.send ,   M2.receive   ,  M3.send  ,  M4.receive  ,  M5.send"
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo
	cp  kdcReference         kdc/kdc
	gcc amal/amal.c          myCrypto.c   -o amal/amal    -lcrypto
	cp  basimReference       basim/basim
	gcc wrappers.c     dispatcher.c -o dispatcher
	ln -f -s ../amal/amalKey.bin        kdc/amalKey.bin
	ln -f -s ../basim/basimKey.bin      kdc/basimKey.bin
	./dispatcher
	@echo
	@echo "======  REFERENCE's   KDC    LOG  ========="
	@cat kdc/logKDC.txt
	@echo
	@echo "======  STUDENT's    Amal   LOG  ========="
	@cat amal/logAmal.txt
	@echo
	@echo "======  REFERENCE's   Basim  LOG  ========="
	@cat basim/logBasim.txt
	@echo
	@echo "======  Comparing Log Files to the Expected Logs  ========="
	@echo
	diff -s    kdc/logKDC.txt        expected/expected_logKDC.txt
	@echo
	diff -s    amal/logAmal.txt      expected/expected_logAMAL.txt
	@echo
	diff -s    basim/logBasim.txt    expected/expected_logBASIM.txt
	@echo

test2: clean
	@echo
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo "2) Testing STUDENT's KDC against REFERENCE's Amal+Basim"
	@echo "   Validates   M1.receive ,   M2.send"
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo
	gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc      -lcrypto
	cp  amalReference        amal/amal
	cp  basimReference       basim/basim
	gcc wrappers.c     dispatcher.c -o dispatcher
	ln -f -s ../amal/amalKey.bin        kdc/amalKey.bin
	ln -f -s ../basim/basimKey.bin      kdc/basimKey.bin
	./dispatcher
	@echo
	@echo "======  STUDENT's    KDC    LOG  ========="
	@cat kdc/logKDC.txt
	@echo
	@echo
	@echo "======  REFERENCE's   Amal   LOG  ========="
	@cat amal/logAmal.txt
	@echo
	@echo "======  REFERENCE's   Basim  LOG  ========="
	@cat basim/logBasim.txt
	@echo
	@echo "======  Comparing Log Files to the Expected Logs  ========="
	@echo
	diff -s    kdc/logKDC.txt        expected/expected_logKDC.txt
	@echo
	diff -s    amal/logAmal.txt      expected/expected_logAMAL.txt
	@echo
	diff -s    basim/logBasim.txt    expected/expected_logBASIM.txt
	@echo

test3: clean
	@echo
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo "3) Testing STUDENT's Basim against REFERENCE's KDC+Amal"
	@echo "   Validates    M3.receive  ,  M4.send  ,  M5.receive"
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo
	cp  kdcReference         kdc/kdc
	cp  amalReference        amal/amal
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto
	gcc wrappers.c     dispatcher.c -o dispatcher
	ln -f -s ../amal/amalKey.bin        kdc/amalKey.bin
	ln -f -s ../basim/basimKey.bin      kdc/basimKey.bin
	./dispatcher
	@echo
	@echo "======  REFERENCE's   KDC    LOG  ========="
	@cat kdc/logKDC.txt
	@echo
	@echo
	@echo "======  REFERENCE's   Amal   LOG  ========="
	@cat amal/logAmal.txt
	@echo
	@echo "======  STUDENT's    Basim  LOG  ========="
	@cat basim/logBasim.txt
	@echo
	@echo "======  Comparing Log Files to the Expected Logs  ========="
	@echo
	diff -s    kdc/logKDC.txt        expected/expected_logKDC.txt
	@echo
	diff -s    amal/logAmal.txt      expected/expected_logAMAL.txt
	@echo
	diff -s    basim/logBasim.txt    expected/expected_logBASIM.txt
	@echo

test4: clean
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo "4) Testing STUDENT's Code all with itself"
	@echo "   Validates   Everything before submission"
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto
	gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc      -lcrypto
	gcc wrappers.c     dispatcher.c -o dispatcher
	ln -f -s ../amal/amalKey.bin        kdc/amalKey.bin
	ln -f -s ../basim/basimKey.bin      kdc/basimKey.bin
	./dispatcher
	@echo
	@echo "======  STUDENT's    KDC    LOG  ========="
	@cat kdc/logKDC.txt
	@echo
	@echo
	@echo "======  STUDENT's    Amal   LOG  ========="
	@cat amal/logAmal.txt
	@echo
	@echo "======  STUDENT's    Basim  LOG  ========="
	@cat basim/logBasim.txt
	@echo
	@echo "======  Comparing Log Files to the Expected Logs  ========="
	@echo
	diff -s    kdc/logKDC.txt        expected/expected_logKDC.txt
	@echo
	diff -s    amal/logAmal.txt      expected/expected_logAMAL.txt
	@echo
	diff -s    basim/logBasim.txt    expected/expected_logBASIM.txt
	@echo

clean:
	rm -f dispatcher   
	rm -f kdc/kdc      kdc/logKDC.txt
	rm -f amal/amal    amal/logAmal.txt  
	rm -f basim/basim  basim/logBasim.txt  


