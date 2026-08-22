export class ApiError extends Error {constructor(message:string,public status?:number){super(message)}}
export async function api<T>(path:string,options?:RequestInit):Promise<T>{
  let response:Response;
  try{response=await fetch('/api'+path,{headers:{'Content-Type':'application/json'},...options})}catch{throw new ApiError('CIRT Lens API is unreachable. Check that the backend is running.')}
  if(!response.ok){let message=`Request failed (${response.status})`;try{const body=await response.json();message=body.detail||body.error?.detail||message;if(typeof message!=='string')message=JSON.stringify(message)}catch{}throw new ApiError(message,response.status)}
  try{return await response.json() as T}catch{throw new ApiError('The API returned malformed data.',response.status)}
}
