export namespace main {
	
	export class Stats {
	    Harmless: number;
	    Malicious: number;
	    Suspicious: number;
	    Undetected: number;
	
	    static createFrom(source: any = {}) {
	        return new Stats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Harmless = source["Harmless"];
	        this.Malicious = source["Malicious"];
	        this.Suspicious = source["Suspicious"];
	        this.Undetected = source["Undetected"];
	    }
	}
	export class AnalysisResults {
	    Success: boolean;
	    Stats: Stats;
	
	    static createFrom(source: any = {}) {
	        return new AnalysisResults(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Success = source["Success"];
	        this.Stats = this.convertValues(source["Stats"], Stats);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class FileInfo {
	    Name: string;
	    Size: number;
	
	    static createFrom(source: any = {}) {
	        return new FileInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Name = source["Name"];
	        this.Size = source["Size"];
	    }
	}
	export class FunctionResult {
	    Success: boolean;
	    Message: string;
	
	    static createFrom(source: any = {}) {
	        return new FunctionResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Success = source["Success"];
	        this.Message = source["Message"];
	    }
	}

}

