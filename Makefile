SRC 	=	Makefile $(wildcard *.conf *.pm *.pl FTN/*.pm RFC/*.pm FM/*.pm)
USHELL	=	zsh
INB_PKT	=	$(wildcard inb/*.pkt)

all:
	@echo "Введите 'make open_project' для открытия проекта"
	@echo "'make pktinfo' для запуска теста pktinfo"

open_project:
	screen -t vim vim $(SRC)



# тесты
pktinfo:
	@for i in $(INB_PKT); do ./pktinfo.pl -m -c -p $$i|iconv -c -f cp866; done
	

.PHONY: all open_project pktinfo
