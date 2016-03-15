
var program = require("commander");
var fs = require("fs");
var crypto = require("crypto");
var path = require("path");

program
	.version('1.0.0')
	.usage("node mask [options] <filename>")
	.option('-f, --force', 'Overwrite output files')
	.option('-p, --password <password>', 'Password','DNqRTjpphSG12')
	.option('-o, --output <output file>', 'Output file base name')
	.option('-d, --decode', 'Force decode')
	.option('-e, --encode', 'Force encode')
	.option('-b, --blocksize <block-size>', 'Block size', 8192)
	.parse(process.argv);

if(program.args.length<1) {
	program.usage();
	process.exit(-1);
	return;
}

var inputFile = program.args[0];
try {
	var inputStat = fs.statSync(inputFile);
	if(!inputStat.isFile)
		return Error(inputFile,"is not a file");
} catch(e) {
	return Error("File ",inputFile,"does not exist.");	
}

var mode;

if(program.decode)
	mode = "decode";
else if(program.encode)
	mode = "encode";
else if(/\.vdh$/i.test(inputFile))
	mode = "decode";
else
	mode = "encode";

function Error() {
	console.error.apply(console,arguments);
	process.exit(-1);
}

const keyBytes =  crypto.createHash('sha256').update(program.password).digest();

function Write32(data,offset,value) {
	data[offset] = (value >> 24) & 0xff;
	data[offset+1] = (value >> 16) & 0xff;
	data[offset+2] = (value >> 8) & 0xff;
	data[offset+3] = value & 0xff;
}

function Read32(data,offset) {
	var v = ((data[offset] << 24) + (data[offset+1] << 16) + (data[offset+2] << 8) + data[offset+3]) >>> 0;
	return v;
}

function IncrementCounter(ivBytes,incr) {
	var lower = (incr  & 0xffffffff) >>> 0;
	var upper = Math.floor(incr / 0x100000000);
	var prev = Read32(ivBytes,12);
	var v = ((prev+lower) & 0xffffffff) >>> 0;
	Write32(ivBytes,12,v);
	if(v<prev)
		upper++;
	if(upper==0)
		return;
	prev = Read32(ivBytes,8);
	v = ((prev+upper) & 0xffffffff) >>> 0;
	Write32(ivBytes,8,v);
	if(v<prev) {
		prev = Read32(ivBytes,4);
		v = ((prev+1) & 0xffffffff) >>> 0;
		Write32(ivBytes,4,v);
		if(v<prev) {
			prev = Read32(ivBytes,0);
			v = ((prev+1) & 0xffffffff) >>> 0;
			Write32(ivBytes,0,v);			
		}
	}
}

var buffer = new Buffer(parseInt(program.blocksize));
var offset = 0;

var totalWritten = 0;

function ProcessNextBlock(fi,fo,ivBytes,callback) {
	function Write(buffer) {
		fs.write(fo,buffer,0,buffer.length,function(err,written) {
			if(err)
				return callback(new Error("Could not write file",program.output,":",err.message));
			totalWritten += written;
			//console.info("Written",written,"bytes","total",totalWritten);
			ProcessNextBlock(fi,fo,ivBytes,callback);
		});		
	}
	function Read() {
		fs.read(fi,buffer,0,buffer.length,null,function(err,bytesRead,buffer) {
			if(err)
				return callback(new Error("Could not read file",program.input,":",err.message));
			//console.info("Read",bytesRead,"bytes",buffer);
			if(bytesRead==0) {
				fs.close(fi);
				fs.close(fo);
				callback(null);
			} else {
				if(mode=="encode")
					Encode(buffer.slice(0,bytesRead));
				else if(mode=="decode")
					Decode(buffer.slice(0,bytesRead));
				offset += bytesRead;
			}
		});		
	}
	function Prepare() {
		var ivBytes2 = new Buffer(16); 
		ivBytes.copy(ivBytes2);
		var prevBlockCount = Math.floor(offset/16);
		IncrementCounter(ivBytes2,prevBlockCount);
		return {
			ivBytes: ivBytes2,
			shift: offset % 16,
		}
	}
	function Decode(buffer) {
		var iv = Prepare();
		var decipher = crypto.createDecipheriv("aes-256-ctr",keyBytes,iv.ivBytes);
		var decrypted = Buffer.concat([decipher.update(new Buffer(iv.shift)),decipher.update(buffer),decipher.final()]).slice(iv.shift,buffer.length+iv.shift);
		//console.info("decrypted",decrypted.length);		
		Write(decrypted);
	}
	function Encode(buffer) {
		var iv = Prepare();
		var cipher = crypto.createCipheriv("aes-256-ctr",keyBytes,iv.ivBytes);
		var crypted = Buffer.concat([cipher.update(new Buffer(iv.shift)),cipher.update(buffer),cipher.final()]).slice(iv.shift,buffer.length+iv.shift);
		//console.info("crypted",crypted.length);
		Write(crypted);
	}
	Read();
}

function Process(inputFile, outputFile, ivBytes, callback) {
	fs.open(inputFile,"r",function(err,fi) {
		if(err)
			return callback(new Error("Cannot open file",inputFile,"for reading:",err.message));
		fs.open(outputFile,"w",function(err,fo) {
			if(err)
				return callback(new Error("Cannot open file",outputFile,"for writing:",err.message));
			ProcessNextBlock(fi,fo,ivBytes,callback);
		});
	});
	
}

if(mode=="encode") {
	var outputFileBase;
	if(program.output) {
		outputFileBase = /^(.*?)(?:\.[^\.]{1,5})?$/.exec(program.output)[1];
		if(!program.force) {
			var outputFiles = [outputFileBase+".vdh",outputFileBase+".bin"];
			for(var i = 0; i<outputFiles.length; i++) {
				var outputFile = outputFiles[i];
				try {
					fs.statSync(outputFile);
					return Error("File ",outputFile,"already exists. Use -f option to overwrite it.");
				} catch(e) {}
			}
		}
	} else
		outputFileBase = (crypto.randomBytes(16)).toString("hex");

	var biniv =  crypto.randomBytes(16);
	Process(inputFile,outputFileBase+".bin",biniv,function(err) {
		if(err)
			return Error(err);
		var metaiv =  crypto.randomBytes(16);
		var manifest = {
			biniv: biniv.toString('base64'),
			metaiv: metaiv.toString('base64'), 
		}
		var meta = {
			originalFilename: path.parse(inputFile).base, 
		}
		var metaBytes = new Buffer(JSON.stringify(meta),"utf8");
		var cipher = crypto.createCipheriv("aes-256-ctr",keyBytes,metaiv);
		var crypted = Buffer.concat([cipher.update(metaBytes),cipher.final()]);
		manifest.meta = crypted.toString('base64');
		var manifestText = JSON.stringify(manifest,null,4);
		fs.writeFile(outputFileBase+".vdh",manifestText,{encoding:"utf8",mode:0o644},function(err) {
			if(err) {
				fs.unlink(ouputFileBase+".bin",function(){});
				return Error("Could not write",ouputFileBase+".vdh",":",err);
			}
			console.info("Files",outputFileBase+".vdh","and",outputFileBase+".bin","have been created");
		});
	});
} else if(mode=="decode") {
	fs.readFile(inputFile,"utf8",function(err,manifestText) {
		if(err)
			return Error("Could not read file",inputFile,":",err);
		var fullFileName = path.resolve(inputFile);
		var parsedPath = path.parse(fullFileName);
		var binFileName = path.resolve(parsedPath.dir,path.basename(fullFileName,parsedPath.ext)+".bin");
		try {
			fs.statSync(binFileName);
		} catch(e) {
			return Error("File ",binFileName,"not found.");			
		}
		
		var manifest;
		try {
			manifest = JSON.parse(manifestText);
		} catch(e) {
			return Error("File",inputFile,"is not in JSON format");
		}
		if(!manifest.biniv || !manifest.metaiv || ! manifest.meta)
			return Error("File",inputFile,"is missing mandatory fields");
		var metaBytes = new Buffer(manifest.meta,"base64");
		var metaiv = new Buffer(manifest.metaiv,"base64");
		var decipher = crypto.createDecipheriv("aes-256-ctr",keyBytes,metaiv);
		var metaText = Buffer.concat([decipher.update(metaBytes),decipher.final()]);
		var meta;
		try {
			meta = JSON.parse(metaText);
		} catch(e) {
			return Error("Meta data are not in JSON format. Files",inputFile,"and",binFileName,"have probably been encoded using a different key.");
		}
		meta.originalFilename = program.output || meta.originalFilename;
		if(!meta.originalFilename)
			meta.originalFilename = (crypto.randomBytes(16)).toString("hex")+"."+(meta.extension || "mp4");
		if(!program.force) {
			try {
				fs.statSync(meta.originalFilename);
				return Error("File ",meta.originalFilename,"already exists. Use -f option to overwrite it.");
			} catch(e) {}
		}		
		var biniv = new Buffer(manifest.biniv,"base64");
		Process(binFileName,meta.originalFilename,biniv,function(err) {
			if(err)
				return Error(err);
			console.info("File",meta.originalFilename,"has been created");
		});
	});
}
