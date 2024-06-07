readme:
	cargo readme -i src/lib.rs -t docs/readme.tpl \
		| perl -ne 's/\[(.+?)\]\((?!https).+?\)/\1/g; print;' \
		| perl -ne 's/(?<!#)\[(.+?)\](?!\()/\1/g; print;' \
		> README.md
