PROGNAME=	tcp-connect-time
LIBS=		-lutil -lpcap -lJudy
CFLAGS=		-I/usr/local/include -g
LDFLAGS=	-L/usr/local/lib ${LIBS}

all:	judy ${PROGNAME}

${PROGNAME}: ${PROGNAME}.o
	${CC} ${LDFLAGS} ${PROGNAME}.o -o ${.TARGET}

clean:
	-rm -f *.o *.core ${PROGNAME}

judy:
.if !exists(/usr/local/lib/libJudy.so)
	@if [ ! -d /usr/ports/devel/judy ]; then \
		echo "Can't find Judy library in ports"; \
		echo ""; \
		exit 1; \
	fi
	make -C /usr/ports/devel/judy clean install clean
.endif
