sojuctl(1)

# NAME

sojuctl - Manage a running instance of the soju IRC bouncer

# SYNOPSIS

*sojuctl* [options...] <command...>

# DESCRIPTION

sojuctl sends a _BouncerServ_ command to a running soju instance. See the
_IRC SERVICE_ section in *soju*(1) for more information.

sojuctl requires a _listen unix+admin://_ directive in the soju configuration
file. sojuctl needs to be run with write permissions on the soju admin socket.

# OPTIONS

*-h, -help*
	Show help message and quit.

*-config* <path>
	Path to the config file. If unset, the default config file path is used,
	if any.

# AUTHORS

Maintained by Simon Ser <contact@emersion.fr>, who is assisted by other
open-source contributors. For more information about soju development, see
<https://soju.im>.

# SEE ALSO

*soju*(1)
