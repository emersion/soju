#!/bin/sh -eu

# Converts a log dir to its case-mapped form.
#
# soju needs to be stopped for this script to work properly. The script may
# re-order messages that happened within the same second interval if merging
# two daily log files is necessary.
#
# usage: casemap-logs.sh <directory>

root="$1"

for net_dir in "$root"/*/*; do
	for chan in $(ls "$net_dir"); do
		cm_chan="$(echo $chan | tr '[:upper:]' '[:lower:]')"
		if [ "$chan" = "$cm_chan" ]; then
			continue
		fi

		if ! [ -d "$net_dir/$cm_chan" ]; then
			echo >&2 "Moving case-mapped channel dir: '$net_dir/$chan' -> '$cm_chan'"
			mv "$net_dir/$chan" "$net_dir/$cm_chan"
			continue
		fi

		echo "Merging case-mapped channel dir: '$net_dir/$chan' -> '$cm_chan'"
		for day in $(ls "$net_dir/$chan"); do
			if ! [ -e "$net_dir/$cm_chan/$day" ]; then
				echo >&2 "  Moving log file: '$day'"
				mv "$net_dir/$chan/$day" "$net_dir/$cm_chan/$day"
				continue
			fi

			echo >&2 "  Merging log file: '$day'"
			sort "$net_dir/$chan/$day" "$net_dir/$cm_chan/$day" >"$net_dir/$cm_chan/$day.new"
			mv "$net_dir/$cm_chan/$day.new" "$net_dir/$cm_chan/$day"
			rm "$net_dir/$chan/$day"
		done

		rmdir "$net_dir/$chan"
	done
done
