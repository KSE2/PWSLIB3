package org.jpws.pwslib.crypto;

import org.jpws.pwslib.global.Global;

public class Test_RandomGen {
    
    static final int RANDOM_SIZE = 100000;
    
    CryptoRandom cra = new CryptoRandom();
    byte[] data;
    int[] valStat = new int[ 256 ];
    int bottom, top, avg, maxDif, minDif, medDif;
    
    
    void populate1 () {
        data = cra.nextBytes( RANDOM_SIZE );
        
    }

    void test1 () {
        int i, sum;
        
        for ( i = 0; i < data.length; i++ ) {
            int b = ((int)data[i]) & 0xFF;
            valStat[b]++;
        }

        // calc top and bottom
        bottom = RANDOM_SIZE;
        top = 0;
        for ( i = 0; i < valStat.length; i++ ) {
            int v = valStat[i];
            if ( v < bottom )
               bottom = v;
            if ( v > top )
               top = v; 
        }
        maxDif = top - bottom;

        // calc average
        sum = 0;
        for ( i = 0; i < valStat.length; i++ ) {
            int v = valStat[i];
            sum += v - bottom;
        }
        avg = bottom + sum / 256;

        // calc deviation
        sum = 0;
        minDif = 256;
        maxDif = 0;
        for ( i = 0; i < valStat.length; i++ ) {
            int v = valStat[i];
            int difAbs = Math.abs( v - avg );
            sum += difAbs;
            
            if ( difAbs < minDif ) 
               minDif = difAbs; 
            if ( difAbs > maxDif ) 
                maxDif = difAbs; 
        }
        medDif = sum / 256;

    }

    void print1 () {
       System.out.println( "TESTING: random Size == " + RANDOM_SIZE + ", Method: random bytes" );
       System.out.println();
       System.out.println( "bottom == " + bottom + ", top == " + top + ", average == " + avg );
       System.out.println( "minDevi == " + minDif + " ("+ minDif*100/avg + "%), maxDevi == " + maxDif + " ("+ maxDif*100/avg + "%), avgDevi == " 
                           + medDif + " ("+ medDif*100/avg + "%)" );
       System.out.println();
       
       // print values
       for ( int i = 0; i < valStat.length; i++ ) {
           int v = valStat[i];
           int dev = v - avg;
           System.out.println( "   " + i + " :  " + v + "   devi == " + dev );
           
       }
       System.out.println( "# print1" );
       
    }
    
    
    void performTest_1 () {
        populate1();
        test1();
        print1();
    }
    
    public static void main ( String args[] ) {
        Global.init();
        new Test_RandomGen().performTest_1();
    }
}
