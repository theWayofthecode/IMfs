implement Xmlpull;

include "sys.m";
	sys: Sys;
include "math.m";
	math: Math;
include "string.m";
	str: String;
include "xmlpull.m";

init(): string
{
	sys = load Sys Sys->PATH;
	math = load Math Math->PATH;
	str = load String String->PATH;
	
	return nil;
}

xmlpull.open(fd: ref Sys->FD, nil: int): ref xmlpull
{
	ret := ref xmlpull;

	ret.la = array[1] of int;
	ret.lv = array[1] of int;
	ret.ln = array[1] of int;
	
	ret.na = nil;
	ret.va = nil;
	ret.lm = nil;
	ret.ln[0] = 0;
	ret.lv[0] = 0;
	ret.la[0] = 0;
	ret.ev = START_DOCUMENT;
	ret.nev = START_DOCUMENT;
	ret.fd = fd;

	return ret;
}

getchara(x: ref xmlpull): byte
{
	g := array[1] of byte;

	n := sys->read(x.fd, g, len g);
	if(n <= 0){
		x.ev = END_DOCUMENT;
		return byte 0;
	}
	return g[0];
}

addchara(b: string, l: array of int, c: byte): string
{
	b[l[0]++] = int c;
	b[l[0]] = '\0';

	return b;
}

readuntilstr(x: ref xmlpull, str: string): string
{
	g: byte;
	u: array of byte;
	p: int;
	
	u = array[len str+1] of byte;
	p = 0;
	while((g = getchara(x)) != byte 0){
		u[p++] = g;
		if(p < len str)
			continue;
		if(string u != str){
			u = nil;
			return x.na;
		}
		p--;
		x.na = addchara(x.na, x.ln, u[0]);
		u = u[1:len str-1];
	}
	u = nil;
	return nil;
}

readuntil(x: ref xmlpull, b: string, l: array of int, w: byte, t: byte): string
{
	g: byte;

	while((g = getchara(x)) != byte 0){
#		sys->print("||%c %c||", int g, int w);
		if(g == w){
			b = addchara(b, l, byte '\0');
			return b;
		}

		case(int g){
		'/' or '>' =>
			if(t != byte 0){
				addchara(b, l, g);
				return nil;
			}
			if(t != byte 0)
				return b;
			b = addchara(b, l, g);
		'\t' or '\r' or '\n' or ' ' =>
			if(t != byte 0)
				return b;
			b = addchara(b, l, g);
		'\\' =>
			g = getchara(x);
			if(g == byte 0)
				return nil;
			b = addchara(b, l, g);
		* =>
			b = addchara(b, l, g);
		}
	}
	return nil;
}

parseattrib(x: ref xmlpull): string
{
	g: byte;
	b: string;

	while((g = getchara(x)) != byte 0){
		#sys->print("%c", int g);
		case(int g){
		'\t' or '\r' or '\n' or ' ' =>
			continue;
		'/' or '>' =>
			x.na = addchara(x.na, x.ln, g);
			return nil;
		* =>
			x.na = addchara(x.na, x.ln, g);
			g = byte 0;
		}
		if(g == byte 0)
			break;
	}

	if((b = readuntil(x, x.na, x.ln, byte '=', byte 2)) == nil)
		return nil;
	x.na = b;

	if((g = getchara(x)) == byte 0)
		return nil;
	#sys->print("magic char: %c\n", int g);

	case(int g){
	'"' or '\'' =>
		if((b = readuntil(x, x.va, x.lv, g, byte 0)) == nil)
			return nil;
		x.va = b;
		return x.va;
	* =>
		if((b = readuntil(x, x.va, x.lv, byte '>', byte 2)) == nil)
			return nil;
		x.va = b;
		return x.na;
	}
	return x.na;
}

readname(x: ref xmlpull): string
{
	g: byte;

	while((g = getchara(x)) != byte 0){
#		sys->print("%c", int g);
		case(int g){
		'\n' or '\t' or '\r' or ' ' or '>' or '/' =>
			x.na = addchara(x.na, x.ln, g);
			return x.na;
		* =>
			x.na = addchara(x.na, x.ln, g);
		}
	}

	return nil;
}

xmlpull.next(x: self ref xmlpull): ref xmlpull
{
	g: byte;

	if(x.va != nil)
		x.va = nil;
	if(x.ev == START_TAG){
		if(x.lm != nil)
			x.lm = nil;
		x.lm = x.na;
		x.la = x.ln;
	}
	else if(x.na != nil)
		x.na = nil;
	x.na = nil;
	x.va = nil;
	x.ln[0] = 0;
	x.lv[0] = 0;
	g = byte '\0';

	case(int x.nev){
	START_DOCUMENT =>
		if((x.na = readuntil(x, x.na, x.ln, byte '<', byte 0)) == nil)
			x.nev = END_DOCUMENT;
		else
			x.nev = START_TAG;
		x.ev = START_DOCUMENT;
	START_TAG =>
		g = getchara(x);
		if(g == byte '/')
			x.ev = END_TAG;
		else{
			x.na = addchara(x.na, x.ln, g);
			x.ev = START_TAG;
		}

		if(readname(x) == nil){
			x.nev = END_DOCUMENT;
		}else{
			if(str->prefix("![CDATA[", x.na)){
				x.na = x.na[8:];
				x.ln[0] -= 8;
				x.na = readuntilstr(x, "]]>");
				x.ev = TEXT;
				x.nev = TEXT;
				return x;
			}
			if(str->prefix("!--", x.na)){
				x.na[x.ln[0]-1] = '\0';
				x.nev = TEXT_C;
				return x;
			}
			if(x.ev == END_TAG){
				x.na[x.ln[0]-1] = '\0';
				x.nev = TEXT;
			}
			else
				case(int x.na[x.ln[0]-1]){
				'/' =>
					getchara(x);
					x.ev = START_END_TAG;
					x.nev = TEXT;
					x.na[x.ln[0]-1] = '\0';
				'>' =>
					x.nev = TEXT;
					x.na[x.ln[0]-1] = '\0';
				* =>
					x.na[x.ln[0]-1] = '\0';
					x.nev = ATTR;
				}
		}
	TEXT or TEXT_C =>
		if(int x.nev == TEXT_C)
			g = byte '>';
		if(g != byte '>')
			g = byte '<';
		if((x.na = readuntil(x, x.na, x.ln, g, byte 0)) == nil){
			x.ev = END_DOCUMENT;
			x.nev = (END_DOCUMENT+1);
		}
		else{
			if(x.nev == TEXT_C)
				x.nev = TEXT;
			else
				x.nev = START_TAG;
			x.ev = TEXT;
		}
	ATTR =>
		if(parseattrib(x) == nil){
			case(int x.na[x.ln[0]-1]){
			'/' =>
				x.na = x.lm;
				x.ln[0] = x.la[0];
				x.lm = nil;
				x.la[0] = 0;

				getchara(x);
				x.ev = END_TAG;
				x.nev = TEXT;
				return x;
			'>' or * =>
				x.na[x.ln[0]-1] = '\0';
			}
			x.ev = ATTR;
			x.nev = TEXT;
			return x.next();
		}
		else
			x.nev = ATTR;
		x.ev = ATTR;
	END_DOCUMENT =>
		x.ev = END_DOCUMENT;
		x.nev = (END_DOCUMENT+1);
	* =>
		return nil;
	}

	return x;
}

xmlpull.write(x: self ref xmlpull): ref xmlpull
{
	b: string;

	b = nil;
	case(int x.nev){
	START_DOCUMENT =>
		if(sys->write(x.fd, array of byte "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", 39) < 0)
			return nil;
		return x;
	START_TAG =>
		if(x.na == nil)
			return nil;
		b = sys->sprint("<%s ", x.na);
		if(sys->write(x.fd, array of byte b, len b) < 0){
			b = nil;
			return nil;
		}
		b = nil;
		return x;
	START_END_TAG =>
		if(x.na == nil)
			return nil;
		b = sys->sprint("<%s/>", x.na);
		if(sys->write(x.fd, array of byte b, len b) < 0){
			b = nil;
			return nil;
		}
		b = nil;
		return x;
	TEXT =>
		if(x.na == nil)
			return nil;
		if(sys->write(x.fd, array of byte x.na, x.ln[0]) < 0)
			return nil;
		return x;
	TEXT_C =>
		if(x.na == nil)
			return nil;
		b = sys->sprint("%s -->", x.na);
		if(sys->write(x.fd, array of byte b, len b) < 0){
			b = nil;
			return nil;
		}
		b = nil;
		return x;
	ATTR =>
		if(x.na == nil)
			return nil;
		if(x.va == nil)
			b = sys->sprint("%s=\"%s\" ", x.na, "");
		else
			b = sys->sprint("%s=\"%s\" ", x.na, x.va);
		if(sys->write(x.fd, array of byte b, len b) < 0){
			b = nil;
			return nil;
		}
		b = nil;
		return x;
	END_TAG =>
		if(x.na == nil)
			return nil;
		b = sys->sprint("</%s>", x.na);
		if(sys->write(x.fd, array of byte b, len b) < 0){
			b = nil;
			return nil;
		}
		b = nil;
		return x;
	END_TAG_S =>
		if(sys->write(x.fd, array of byte "/>", 2) < 0)
			return nil;
		return x;
	END_TAG_N =>
		if(sys->write(x.fd, array of byte ">", 1) < 0)
			return nil;
		return x;
	END_DOCUMENT =>
		x.fd = nil;
		return nil;
	}
	return nil;
}

