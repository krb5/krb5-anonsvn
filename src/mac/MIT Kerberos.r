#include "Types.r"

/*--vend ¥ Vendor Information Template (for Conflict Catcher) -----------------------*/
type 'vend' {
		longint;												/* version (0) */
		pstring;												/* name */
		pstring;												/* address */
		pstring;												/* voice phone */
		pstring;												/* fax phone */
		pstring;												/* update URL	*/
		pstring;												/* info URL */
		pstring;												/* e-mail URL */
};

resource 'vers' (2, purgeable) {
	2,
	01,
	final,
	0,
	verUS,
	"2.0.1",
	"MIT Kerberos for the Macintosh 2.0.1"
};

resource 'vend' (-20640, purgeable) {
	0,
	"MIT Information Systems MacDev",
	"77 Massachusetts Avenue, E40-318, Cambridge, MA 02139",
	"",
	"",
	"",
	"http://mit.edu/macdev/www/",
	"mailto:macdev@mit.edu"
};
