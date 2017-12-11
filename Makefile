make:
	g++ -std=c++11 -o pds-scanner main-scanner.cpp types.h pds-scanner.cpp pds-scanner.hpp packet.cpp packet.hpp xml/rapidxml.hpp xml/rapidxml_print.hpp manipulateXml.cpp manipulateXml.hpp -lpcap
	g++ -std=c++11 -o pds-spoof main-spoof.cpp types.h pds-scanner.cpp pds-scanner.hpp packet.cpp packet.hpp manipulateXml.cpp manipulateXml.hpp pds-spoof.cpp pds-spoof.hpp xml/rapidxml.hpp xml/rapidxml_print.hpp -lpcap
	g++ -std=c++11 -o pds-intercept main-intercept.cpp types.h pds-scanner.cpp pds-scanner.hpp packet.cpp packet.hpp manipulateXml.cpp manipulateXml.hpp pds-spoof.cpp pds-spoof.hpp pds-intercept.cpp pds-intercept.hpp xml/rapidxml.hpp xml/rapidxml_print.hpp -lpcap

clean:
	rm pds-intercept
	rm pds-scanner
	rm pds-spoof
	rm *.xml