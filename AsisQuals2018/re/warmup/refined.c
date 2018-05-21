#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#define M 37
#define	q (2+M/M)
#define	v (q/q)
#define	ef ((v+q)/2)
#define	f (q-v-ef)
#define k (8-ef)

struct b
{
	int64_t y[13];
}S;

int m=1811939329, N=1, t[1<<26]={2} ,a ,*p,i,e=73421233,s,c,U=1;
g(d,h)
{
	for(i=s;i<1<<25;i*=2)
	d=d*1LL*d%m;
	for(p=t;p<t+N;p+=s)
	for(i=s,c=1;i;i--)a=p[s]*(h?c:1LL)%m,p[s]=(m*1U+*p-a)*(h?1LL:c)%m,*p=(a*1U+*p)%m,p++,c=c*1LL*d%m;
}
l()
{
	while(e/=2)
	{
		N*=2;
		U=U*1LL*(m+1)/2%m;
		for(s=N; s/=2;)
		g(136,0);
		for(p=t;p<t+N;p++) *p=*p*1LL**p%m*U%m;
		for(s=1;s<N;s*=2)
		g(839354248,1);
		for(a=0,p=t;p<t+N;)a+=*p<<(e&1),*p++=a%10,a/=10;
	}
}

	z(n)
{
	int y=3,j,c;
	for(j=2;j<=n;)
	{
//	l();
	for(c=2;c<=y-1;c++)
		{
//			l();
			if(y%c==0)break;
		}
		if(c==y)
		{
//			l();
			j++;
		}
		y++;
	}
//	l();
	return y-1;
}
	main(a, pq) 
	char* pq;
{
	int b=sizeof(S),y=b,j=M;
//	l();
	int x[M]=
	{
		b-M-sizeof((short int) a),(b>>v)+(k<<v)+ (v<<(q|ef)) + z(v+(ef<<v)),(z(k*ef)<<v)-pow(ef,f), z(( (j-ef*k)|(ef<<k>>v)/k-ef<<v)-ef),(((y+M)&b)<<(k/q+ef))-z(ef+v),((ef<<k)-v)&y,y*v+v,(ef<<(q*ef-v-(k>>ef)))*q-v,(f<<q)|(ef<<(q*f+k))-j+k,(z(z(z(z(z(v)))))*q)&(((j/q)-(ef<<v))<<q)|(j+(q|(ef<<v))),y|(q+v),(ef<<ef)-v+ef*(((j>>ef)|j)-v+ef-q+v),(z(j&(b<<ef))&(z(v<<v)<<k))-(q<<v)-q,(k<<q)+q,(z(y)>>(ef<<v))+(z(k+v))-q,(z(z(k&ef|j))&b|ef|v<<f<<q<<v&ef>>k|q<<ef<<v|k|q)+z(v<<v)+v,(ef>>v)*q*z(k-v)+z(ef<<ef&q|k)+ef,z(k<<k)&v&k|y+k-v,z(f>>ef|k>>ef|v|k)*(ef>>v)*q,(ef<<k-ef<<v>>q<<ef*ef)-j+(ef<<v),z(ef*k)*z(v<<v)+k-v,z((z(k)<<z(v)))&y|k|v,z(ef<<ef<<v<<v)/ef+z(v<<ef|k|(b>>q)&y-f)-(ef<<q)+(k-v)-ef,k<<(ef+q)/z(ef)*z(q)&z(k<<k)|v,((z(y|j>>k*ef))%ef<<z(v<<v<<v)>>q<<q|j)/ef+v,(j-ef<<ef<<v*z(v>>v<<v)>>ef)/ef%z(k<<j)+q,z(k-v)+k|z(ef<<k>>v<<f)-z(q<<q)*ef>>v,(z(ef|y&j|k)%q|j+ef<<z(k|ef)%k<<q|ef|k<<ef<<q/ef|y/ef+j>>q)&k<<j|ef+v,84,z(v*ef<<ef<<q)*q%ef<<k|k|q-v,((z(20)*v)|(f>>q)|(k<<k))/ef-(ef<<(v*q+ef))-(k<<q)+z(k)-q
	};
	while(j--)
	{
		putchar(x[M-v-j]);	
	}
	printf(" From ASIS With Love <3\n");
	return 0;
}