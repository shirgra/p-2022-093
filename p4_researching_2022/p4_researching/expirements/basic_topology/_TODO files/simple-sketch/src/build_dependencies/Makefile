all: topology_configuration_file

topology_configuration_file: topology_configuration_file.p4
	p4c-bm2-ss --std p4-16 \
		--target bmv2 --arch v1model \
		-o topology_configuration_file.json \
		--p4runtime-file topology_configuration_file.p4info \
		--p4runtime-format text topology_configuration_file.p4 \
		--Wdisable

